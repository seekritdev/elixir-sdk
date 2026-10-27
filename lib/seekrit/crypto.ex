defmodule Seekrit.Crypto do
  @moduledoc """
  Zero-knowledge read path, byte-compatible with `@seekrit/crypto` and
  `crates/seekrit-core`. Three steps:

    1. Recover the service token's P-256 private key — `parse_token_key/1`.
    2. Unwrap each environment DEK — `unwrap_dek/2`.
    3. Decrypt each secret — `decrypt_secret/3`.

  Blob formats (all segments base64url, no padding):

      token       skt_<id>_v2.<auth secret>.<pkcs8 private key>
      wrapped DEK wd1.<ephemeral pub (raw SEC1)>.<hkdf salt>.<iv>.<ciphertext||tag>
      secret      sc1.<iv>.<ciphertext||tag>

  Everything here is pure OTP: `:crypto` for ECDH/HMAC/AES-GCM and
  `:public_key` for the PKCS#8 token key. No NIFs, no dependencies.
  """

  alias Seekrit.{CryptoError, Interpolate}

  @hkdf_info "seekrit/wrap-dek/v1"
  @curve :secp256r1
  @p256_oid {1, 2, 840, 10045, 3, 1, 7}
  @tag_bytes 16

  # Only the first two underscores are separators; the key segment may contain "_".
  @auth_re ~r/\A(skt_[0-9A-Za-z]+_v2\.[A-Za-z0-9_-]{43})(?:\.[A-Za-z0-9_-]+)?\z/
  @token_re ~r/\A(skt_[0-9A-Za-z]+)_(?:v2\.[A-Za-z0-9_-]{43}\.)?([A-Za-z0-9_-]+)\z/

  @doc "Extract the v2 wire credential without exposing the private key."
  def service_token_auth(token) do
    case Regex.run(@auth_re, token) do
      [_, auth] ->
        {:ok, auth}

      _ ->
        crypto_error(
          "a v2 service token is required for API access; replace legacy tokens in the dashboard"
        )
    end
  end

  defmodule TokenKey do
    @moduledoc """
    The P-256 private key recovered from a `skt_…` service token.

    Inspecting one prints only the token id — the private scalar must never
    reach a log line or a crash report.
    """
    defstruct [:token_id, :private_key]

    @type t :: %__MODULE__{token_id: String.t(), private_key: binary()}

    defimpl Inspect do
      import Inspect.Algebra

      def inspect(%{token_id: id}, opts) do
        concat(["#Seekrit.TokenKey<", to_doc(id, opts), ", private_key: [REDACTED]>"])
      end
    end
  end

  @doc """
  Recover the P-256 private key from a `skt_…` service token.
  """
  @spec parse_token_key(String.t()) :: {:ok, TokenKey.t()} | {:error, CryptoError.t()}
  def parse_token_key(token) when is_binary(token) do
    with [_, token_id, key_b64] <- Regex.run(@token_re, token),
         {:ok, der} <- b64url_decode(key_b64, "service token private key is corrupted"),
         {:ok, scalar} <- ec_private_scalar(der) do
      {:ok, %TokenKey{token_id: token_id, private_key: scalar}}
    else
      nil -> crypto_error("not a valid seekrit service token")
      {:error, _} = error -> error
    end
  end

  def parse_token_key(_), do: crypto_error("not a valid seekrit service token")

  # PKCS#8 PrivateKeyInfo -> the raw 32-byte scalar. `pem_entry_decode/1` does
  # the unwrapping and lifts the curve out of the algorithm identifier, so the
  # inner ECPrivateKey's optional `parameters` field is populated either way.
  # Matched by position (RFC 5915 field order) rather than by record, so a new
  # trailing field in a future OTP release cannot break the match.
  defp ec_private_scalar(der) do
    case :public_key.pem_entry_decode({:PrivateKeyInfo, der, :not_encrypted}) do
      key when is_tuple(key) and elem(key, 0) == :ECPrivateKey ->
        if named_curve(elem(key, 3)) == @p256_oid do
          {:ok, elem(key, 2)}
        else
          crypto_error("service token key is not on the P-256 curve")
        end

      _ ->
        crypto_error("service token key is not an EC private key")
    end
  rescue
    _ -> crypto_error("service token private key is corrupted")
  catch
    _, _ -> crypto_error("service token private key is corrupted")
  end

  # OTP spells the curve either as its OID or as an atom, depending on version.
  defp named_curve({:namedCurve, :secp256r1}), do: @p256_oid
  defp named_curve({:namedCurve, :prime256v1}), do: @p256_oid
  defp named_curve({:namedCurve, oid}), do: oid
  defp named_curve(_), do: nil

  @doc """
  Recover a 32-byte environment DEK from a `wd1.` blob.
  """
  @spec unwrap_dek(TokenKey.t(), String.t()) :: {:ok, binary()} | {:error, CryptoError.t()}
  def unwrap_dek(%TokenKey{private_key: scalar}, wrapped) when is_binary(wrapped) do
    with {:ok, [eph, salt, iv, ciphertext]} <- split_blob(wrapped, "wd1", 4),
         {:ok, shared} <- ecdh(scalar, eph),
         wrapping_key = hkdf_sha256(shared, salt, @hkdf_info, 32),
         {:ok, dek} <-
           aes_gcm_decrypt(
             wrapping_key,
             iv,
             ciphertext,
             "",
             "DEK unwrap failed: wrong private key or tampered grant"
           ) do
      if byte_size(dek) == 32,
        do: {:ok, dek},
        else: crypto_error("unwrapped DEK has wrong length")
    end
  end

  defp ecdh(scalar, ephemeral_public) do
    {:ok, :crypto.compute_key(:ecdh, ephemeral_public, scalar, @curve)}
  rescue
    _ -> crypto_error("DEK unwrap failed: bad ephemeral key")
  end

  @doc """
  Decrypt an `sc1.` secret ciphertext to its UTF-8 plaintext.

  `aad` binds the ciphertext to its environment and name — see `secret_aad/2`.
  """
  @spec decrypt_secret(binary(), String.t(), binary()) ::
          {:ok, String.t()} | {:error, CryptoError.t()}
  def decrypt_secret(dek, blob, aad) when is_binary(blob) do
    with {:ok, [iv, ciphertext]} <- split_blob(blob, "sc1", 2) do
      aes_gcm_decrypt(
        dek,
        iv,
        ciphertext,
        aad,
        "secret decryption failed: wrong key, tampered data, or mismatched context"
      )
    end
  end

  @doc """
  The AAD binding a secret ciphertext to its environment and name.
  """
  @spec secret_aad(String.t(), String.t()) :: binary()
  def secret_aad(environment_id, name), do: environment_id <> "/" <> name

  @doc """
  Decrypt every layer and merge by precedence.

  Layers arrive lowest precedence first (composed groups, then the app
  environment); later layers overwrite earlier ones on a name collision.

  `${OTHER_SECRET}` references are then expanded over the merged result (so a
  reference sees whichever layer won the name). Pass `interpolate: false` to get
  the stored text instead.
  """
  @spec materialize(map(), TokenKey.t(), keyword()) ::
          {:ok, %{optional(String.t()) => String.t()}}
          | {:error, CryptoError.t() | Seekrit.ReferenceError.t()}
  def materialize(resolve_response, %TokenKey{} = key, opts \\ []) do
    layers = Map.get(resolve_response, "layers") || []

    with {:ok, merged} <- reduce_layers(layers, key) do
      if Keyword.get(opts, :interpolate, true) do
        with {:ok, result} <- Interpolate.interpolate_secrets(merged), do: {:ok, result.values}
      else
        {:ok, merged}
      end
    end
  end

  defp reduce_layers(layers, key) do
    Enum.reduce_while(layers, {:ok, %{}}, fn layer, {:ok, merged} ->
      case decrypt_layer(layer, key, merged) do
        {:ok, merged} -> {:cont, {:ok, merged}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp decrypt_layer(layer, key, merged) do
    with {:ok, dek} <- unwrap_dek(key, Map.fetch!(layer, "wrappedDek")) do
      environment_id = Map.fetch!(layer, "environmentId")

      Enum.reduce_while(Map.get(layer, "secrets") || [], {:ok, merged}, fn secret, {:ok, acc} ->
        name = Map.fetch!(secret, "name")

        case decrypt_secret(
               dek,
               Map.fetch!(secret, "ciphertext"),
               secret_aad(environment_id, name)
             ) do
          {:ok, value} -> {:cont, {:ok, Map.put(acc, name, value)}}
          {:error, _} = error -> {:halt, error}
        end
      end)
    end
  end

  @doc """
  HKDF-SHA256 (RFC 5869), built from `:crypto.mac/4`.

  OTP does expose `:crypto.hkdf/4` on recent releases, but only when the linked
  OpenSSL provides it — this is two lines of HMAC and always there.
  """
  @spec hkdf_sha256(binary(), binary(), binary(), pos_integer()) :: binary()
  def hkdf_sha256(ikm, salt, info, length) do
    prk = :crypto.mac(:hmac, :sha256, salt, ikm)

    1..ceil(length / 32)
    |> Enum.reduce({<<>>, <<>>}, fn counter, {okm, block} ->
      block = :crypto.mac(:hmac, :sha256, prk, block <> info <> <<counter>>)
      {okm <> block, block}
    end)
    |> elem(0)
    |> binary_part(0, length)
  end

  defp aes_gcm_decrypt(key, iv, ciphertext_and_tag, aad, failure_message) do
    if byte_size(ciphertext_and_tag) < @tag_bytes do
      crypto_error("ciphertext too short")
    else
      body = binary_part(ciphertext_and_tag, 0, byte_size(ciphertext_and_tag) - @tag_bytes)

      tag =
        binary_part(ciphertext_and_tag, byte_size(ciphertext_and_tag) - @tag_bytes, @tag_bytes)

      case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, body, aad, tag, false) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        _ -> crypto_error(failure_message)
      end
    end
  rescue
    # A wrong-length key or IV raises rather than returning :error.
    _ -> crypto_error(failure_message)
  end

  defp split_blob(blob, prefix, segments) do
    case String.split(blob, ".") do
      [^prefix | parts] when length(parts) == segments ->
        if Enum.any?(parts, &(&1 == "")) do
          crypto_error(~s(malformed "#{prefix}" blob))
        else
          decode_segments(parts, prefix, [])
        end

      [^prefix | _] ->
        crypto_error(~s(malformed "#{prefix}" blob))

      [got | _] ->
        crypto_error(~s(expected a "#{prefix}" blob, got "#{got}"))
    end
  end

  defp decode_segments([], _prefix, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_segments([segment | rest], prefix, acc) do
    case b64url_decode(segment, ~s(malformed "#{prefix}" blob)) do
      {:ok, bytes} -> decode_segments(rest, prefix, [bytes | acc])
      {:error, _} = error -> error
    end
  end

  defp b64url_decode(text, message) do
    case Base.url_decode64(text, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> crypto_error(message)
    end
  end

  defp crypto_error(message), do: {:error, %CryptoError{message: message}}
end
