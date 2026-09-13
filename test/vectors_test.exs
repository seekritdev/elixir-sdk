defmodule Seekrit.VectorsTest do
  @moduledoc """
  Cross-implementation parity: decrypt the shared golden vectors and assert we
  recover exactly what the canonical `@seekrit/crypto` (WebCrypto) produced.

  `testdata/vectors.json` is a copy of the one canonical fixture every seekrit
  client is pinned to; regenerating it turns this red until the Elixir path
  matches again.
  """
  use ExUnit.Case, async: true

  alias Seekrit.{Crypto, Interpolate}

  @fixture Path.expand("../testdata/vectors.json", __DIR__)
  @external_resource @fixture
  @vectors @fixture |> File.read!() |> JSON.decode!()

  setup_all do
    {:ok, key} = Crypto.parse_token_key(@vectors["token"])
    {:ok, key: key, resolve: @vectors["resolve"]}
  end

  test "the token id round-trips", %{key: key} do
    assert key.token_id == @vectors["tokenId"]
  end

  test "materialize matches expected", %{key: key, resolve: resolve} do
    assert {:ok, merged} = Crypto.materialize(resolve, key)
    assert merged == @vectors["expectedManagedValues"]
  end

  test "app layer wins over group", %{key: key, resolve: resolve} do
    assert {:ok, %{"SHARED" => "from-app"}} = Crypto.materialize(resolve, key)
  end

  test "unicode and empty round-trip", %{key: key, resolve: resolve} do
    assert {:ok, merged} = Crypto.materialize(resolve, key)
    assert merged["UNICODE"] == "héllo-🌍-\n-tab\tend"
    assert merged["EMPTY"] == ""
    assert String.valid?(merged["UNICODE"])
  end

  test "secret references expand over the merged set", %{key: key, resolve: resolve} do
    assert {:ok, merged} = Crypto.materialize(resolve, key)
    assert merged["REFERENCING"] == "url=postgres://group/db;shared=from-app"
    assert merged["ESCAPED_REF"] == "${SHARED}"
    assert merged["DANGLING_REF"] == "build-${NOT_A_SECRET}"
  end

  test "interpolate: false returns the stored text", %{key: key, resolve: resolve} do
    assert {:ok, merged} = Crypto.materialize(resolve, key, interpolate: false)
    assert merged["REFERENCING"] == "url=${DATABASE_URL};shared=${SHARED}"
  end

  for %{"name" => name} = testcase <- @vectors["interpolation"]["cases"] do
    @testcase testcase
    test "interpolation: #{name}" do
      assert {:ok, result} = Interpolate.interpolate_secrets(@testcase["input"])
      assert result.values == @testcase["expected"]
      assert result.unresolved == @testcase["unresolved"]
    end
  end

  for %{"name" => name} = testcase <- @vectors["interpolation"]["cycles"] do
    @testcase testcase
    test "interpolation rejects: #{name}" do
      assert {:error, %Seekrit.ReferenceError{code: :cycle}} =
               Interpolate.interpolate_secrets(@testcase["input"])
    end
  end

  test "tampered grant is rejected", %{key: key, resolve: resolve} do
    # A single-character flip in the wrapped-DEK ciphertext must fail the GCM
    # tag, not silently yield a wrong value.
    [layer | rest] = resolve["layers"]
    blob = layer["wrappedDek"]
    last = String.last(blob)
    tampered = String.slice(blob, 0..-2//1) <> if last == "A", do: "B", else: "A"

    resolve = %{resolve | "layers" => [%{layer | "wrappedDek" => tampered} | rest]}

    assert {:error, %Seekrit.CryptoError{}} = Crypto.materialize(resolve, key)
  end

  test "a tampered secret ciphertext is rejected", %{key: key, resolve: resolve} do
    [layer | rest] = resolve["layers"]
    [secret | others] = layer["secrets"]
    blob = secret["ciphertext"]
    last = String.last(blob)
    tampered = String.slice(blob, 0..-2//1) <> if last == "A", do: "B", else: "A"

    layer = %{layer | "secrets" => [%{secret | "ciphertext" => tampered} | others]}
    resolve = %{resolve | "layers" => [layer | rest]}

    assert {:error, %Seekrit.CryptoError{}} = Crypto.materialize(resolve, key)
  end

  test "a secret decrypted under the wrong name fails its AAD", %{key: key, resolve: resolve} do
    layer = hd(resolve["layers"])
    secret = hd(layer["secrets"])
    {:ok, dek} = Crypto.unwrap_dek(key, layer["wrappedDek"])

    aad = Crypto.secret_aad(layer["environmentId"], "WRONG_NAME")

    assert {:error, %Seekrit.CryptoError{}} =
             Crypto.decrypt_secret(dek, secret["ciphertext"], aad)
  end

  test "a malformed token is rejected" do
    assert {:error, %Seekrit.CryptoError{}} = Crypto.parse_token_key("nope")
    assert {:error, %Seekrit.CryptoError{}} = Crypto.parse_token_key("skt_abc_@@@")
  end

  test "a token key never reaches inspect output", %{key: key} do
    inspected = inspect(key)
    assert inspected =~ "REDACTED"
    refute inspected =~ Base.encode16(key.private_key, case: :lower)
  end
end
