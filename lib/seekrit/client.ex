defmodule Seekrit.Client do
  @moduledoc """
  A read-only seekrit client bound to one service token.

  A service token selects exactly one app environment (plus its composed group
  slices) — that scope is the client's blast radius.

      {:ok, client} = Seekrit.Client.new()      # token from $SEEKRIT_TOKEN
      {:ok, secrets} = Seekrit.Client.resolve(client)
      secrets["DATABASE_URL"]

  Secrets are decrypted in this process; the API only ever sees ciphertext.
  """

  alias Seekrit.{ApiError, Crypto, Error}

  @default_api_url "https://api.seekrit.dev"
  @default_connect_timeout 10_000
  @default_timeout 30_000

  @enforce_keys [:token, :key, :api_url]
  defstruct [
    :token,
    :key,
    :api_url,
    overrides: %{},
    connect_timeout: @default_connect_timeout,
    timeout: @default_timeout,
    interpolate: true,
    ssl_options: nil
  ]

  @type t :: %__MODULE__{
          token: String.t(),
          key: Crypto.TokenKey.t(),
          api_url: String.t(),
          overrides: %{optional(String.t()) => String.t()},
          connect_timeout: timeout(),
          timeout: timeout(),
          interpolate: boolean(),
          ssl_options: keyword() | nil
        }

  @type secrets :: %{optional(String.t()) => String.t()}

  # A client holds a live credential; keep it out of logs and crash reports.
  defimpl Inspect do
    import Inspect.Algebra

    def inspect(%{api_url: api_url, key: key}, opts) do
      concat([
        "#Seekrit.Client<",
        to_doc(api_url, opts),
        ", token: [REDACTED] (",
        to_doc(key.token_id, opts),
        ")>"
      ])
    end
  end

  @doc """
  Build a client.

  ## Options

    * `:token` — `skt_…` service token. Defaults to `$SEEKRIT_TOKEN`.
    * `:api_url` — API base URL. Defaults to `$SEEKRIT_API_URL`, then
      `#{@default_api_url}`.
    * `:with` — `%{group_slug => env_slug}` overrides (the `?with=` override).
      You can only pull a slice your token holds a key for.
    * `:connect_timeout` / `:timeout` — milliseconds. Default
      `#{@default_connect_timeout}` / `#{@default_timeout}`.
    * `:interpolate` — expand `${OTHER_SECRET}` references in resolved values
      (default `true`); `false` returns the stored text verbatim.
    * `:ssl_options` — replace the TLS options entirely (for a private CA).
      The default verifies the peer against the system trust store.

  The token is parsed here, so a malformed one fails before any request.
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, Error.t() | Seekrit.CryptoError.t()}
  def new(opts \\ []) do
    token = Keyword.get(opts, :token) || System.get_env("SEEKRIT_TOKEN")

    if is_nil(token) or token == "" do
      {:error, %Error{message: "no service token: pass :token or set SEEKRIT_TOKEN"}}
    else
      with {:ok, key} <- Crypto.parse_token_key(token),
           {:ok, auth} <- Crypto.service_token_auth(token) do
        {:ok,
         %__MODULE__{
           token: auth,
           key: key,
           api_url: api_url(opts),
           overrides: normalize_overrides(Keyword.get(opts, :with, %{})),
           connect_timeout: Keyword.get(opts, :connect_timeout, @default_connect_timeout),
           timeout: Keyword.get(opts, :timeout, @default_timeout),
           interpolate: Keyword.get(opts, :interpolate, true),
           ssl_options: Keyword.get(opts, :ssl_options)
         }}
      end
    end
  end

  @doc """
  Like `new/1`, but raises instead of returning `{:error, exception}`.
  """
  @spec new!(keyword()) :: t()
  def new!(opts \\ []) do
    case new(opts) do
      {:ok, client} -> client
      {:error, error} -> raise error
    end
  end

  @doc """
  Fetch, decrypt, and merge; returns `{:ok, %{"NAME" => value}}`.

  Fail-closed: a bad token, an unreachable API, or a layer that will not
  decrypt returns an error rather than partial results.
  """
  @spec resolve(t()) :: {:ok, secrets()} | {:error, Exception.t()}
  def resolve(%__MODULE__{} = client) do
    with {:ok, response} <- fetch(client) do
      Crypto.materialize(response, client.key, interpolate: client.interpolate)
    end
  end

  @doc """
  Like `resolve/1`, but raises instead of returning `{:error, exception}`.
  """
  @spec resolve!(t()) :: secrets()
  def resolve!(%__MODULE__{} = client) do
    case resolve(client) do
      {:ok, secrets} -> secrets
      {:error, error} -> raise error
    end
  end

  @doc """
  Resolve and return a single secret's value, or `default` if the name is absent.

  Raises on a resolve or decrypt failure — an absent name and a failed resolve
  are different things, and only the first is allowed to fall back.
  """
  @spec get!(t(), String.t(), String.t() | nil) :: String.t() | nil
  def get!(%__MODULE__{} = client, name, default \\ nil) do
    Map.get(resolve!(client), name, default)
  end

  @doc """
  Load resolved secrets into the OS environment with `System.put_env/2`.

  Existing variables are kept unless `override: true`. Returns the resolved
  secrets on success.
  """
  @spec into_env(t(), keyword()) :: {:ok, secrets()} | {:error, Exception.t()}
  def into_env(%__MODULE__{} = client, opts \\ []) do
    override = Keyword.get(opts, :override, false)

    with {:ok, secrets} <- resolve(client) do
      Enum.each(secrets, fn {name, value} ->
        if override or is_nil(System.get_env(name)), do: System.put_env(name, value)
      end)

      {:ok, secrets}
    end
  end

  @doc """
  Like `into_env/2`, but raises instead of returning `{:error, exception}`.
  """
  @spec into_env!(t(), keyword()) :: secrets()
  def into_env!(%__MODULE__{} = client, opts \\ []) do
    case into_env(client, opts) do
      {:ok, secrets} -> secrets
      {:error, error} -> raise error
    end
  end

  ## HTTP

  defp fetch(client) do
    url = client.api_url <> "/v1/resolve" <> query_string(client.overrides)

    with :ok <- ensure_http_started() do
      request = {String.to_charlist(url), auth_headers(client.token)}

      case :httpc.request(:get, request, http_options(client, url), body_format: :binary) do
        {:ok, {{_version, status, _reason}, _headers, body}} when status in 200..299 ->
          decode_body(body)

        {:ok, {{_version, status, _reason}, _headers, body}} ->
          {:error, api_error(status, body)}

        {:error, reason} ->
          {:error, %Error{message: "resolve request failed: #{inspect(reason)}"}}
      end
    end
  end

  # `:inets` and `:ssl` are not started in a release before the application
  # boots, which is exactly where `config/runtime.exs` calls us from.
  defp ensure_http_started do
    with {:ok, _} <- Application.ensure_all_started(:inets),
         {:ok, _} <- Application.ensure_all_started(:ssl) do
      :ok
    else
      {:error, reason} ->
        {:error, %Error{message: "could not start the HTTP stack: #{inspect(reason)}"}}
    end
  end

  defp auth_headers(token) do
    [
      {~c"authorization", String.to_charlist("Bearer " <> token)},
      {~c"accept", ~c"application/json"}
    ]
  end

  defp http_options(client, url) do
    base = [
      timeout: client.timeout,
      connect_timeout: client.connect_timeout,
      autoredirect: false
    ]

    if String.starts_with?(url, "https://"),
      do: [{:ssl, client.ssl_options || default_ssl_options()} | base],
      else: base
  end

  # `:httpc` does not verify certificates unless told to, and an unverified
  # connection is a silent downgrade of the whole token-bearing request.
  defp default_ssl_options do
    [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      depth: 3,
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ],
      versions: [:"tlsv1.2", :"tlsv1.3"]
    ]
  end

  defp query_string(overrides) when map_size(overrides) == 0, do: ""

  defp query_string(overrides) do
    query =
      overrides
      |> Enum.sort()
      |> Enum.map(fn {group, env} -> {"with", "#{group}:#{env}"} end)
      |> URI.encode_query()

    "?" <> query
  end

  defp normalize_overrides(overrides) do
    Map.new(overrides, fn {group, env} -> {to_string(group), to_string(env)} end)
  end

  defp decode_body(body) do
    case JSON.decode(body) do
      {:ok, response} when is_map(response) ->
        {:ok, response}

      _ ->
        {:error, %Error{message: "resolve returned a body that is not a JSON object"}}
    end
  end

  defp api_error(status, body) do
    case JSON.decode(body) do
      {:ok, %{"error" => %{"code" => code} = error}} when is_binary(code) ->
        %ApiError{status: status, code: code, detail: error["message"] || "HTTP #{status}"}

      _ ->
        %ApiError{status: status, code: "internal", detail: "HTTP #{status}"}
    end
  end

  defp api_url(opts) do
    (Keyword.get(opts, :api_url) || System.get_env("SEEKRIT_API_URL") || @default_api_url)
    |> String.replace(~r{/+\z}, "")
  end
end
