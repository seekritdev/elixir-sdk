defmodule Seekrit.ClientTest do
  @moduledoc """
  The transport half, against a one-shot TCP server: the request we send, and
  what we make of the response. Everything below the JSON is covered by
  `Seekrit.VectorsTest`.
  """
  use ExUnit.Case, async: false

  alias Seekrit.{ApiError, Client, Error}

  @fixture Path.expand("../testdata/vectors.json", __DIR__)
  @external_resource @fixture
  @vectors @fixture |> File.read!() |> JSON.decode!()

  setup do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1}
      ])

    {:ok, port} = :inet.port(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, listener: listener, api_url: "http://127.0.0.1:#{port}"}
  end

  defp serve(listener, status, body) do
    test = self()

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listener, 5_000)
      send(test, {:request, read_request(socket, "")})

      :gen_tcp.send(socket, [
        "HTTP/1.1 #{status} STATUS\r\n",
        "content-type: application/json\r\n",
        "content-length: #{byte_size(body)}\r\n",
        "connection: close\r\n\r\n",
        body
      ])

      :gen_tcp.close(socket)
    end)
  end

  defp read_request(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      acc
    else
      {:ok, chunk} = :gen_tcp.recv(socket, 0, 5_000)
      read_request(socket, acc <> chunk)
    end
  end

  defp client!(opts), do: Client.new!(Keyword.put_new(opts, :token, @vectors["token"]))

  test "resolves, decrypts, and sends the token as a bearer credential", context do
    serve(context.listener, 200, JSON.encode!(@vectors["resolve"]))
    client = client!(api_url: context.api_url)

    assert {:ok, secrets} = Client.resolve(client)
    assert secrets == @vectors["expectedManagedValues"]

    assert_received {:request, request}
    assert request =~ "GET /v1/resolve HTTP/1.1"
    assert request =~ "authorization: Bearer #{@vectors["authToken"]}"
    refute request =~ List.last(String.split(@vectors["token"], "."))
    assert request =~ "accept: application/json"
  end

  test "`with:` becomes a sorted, repeated ?with=group:env query", context do
    serve(context.listener, 200, JSON.encode!(@vectors["resolve"]))
    client = client!(api_url: context.api_url, with: %{"shared" => "dev", "auth" => "staging"})

    assert {:ok, _} = Client.resolve(client)
    assert_received {:request, request}
    assert request =~ "GET /v1/resolve?with=auth%3Astaging&with=shared%3Adev HTTP/1.1"
  end

  test "a trailing slash on the API URL does not double up", context do
    serve(context.listener, 200, JSON.encode!(@vectors["resolve"]))
    assert {:ok, _} = Client.resolve(client!(api_url: context.api_url <> "///"))
    assert_received {:request, request}
    assert request =~ "GET /v1/resolve HTTP/1.1"
  end

  test "auth credentials cannot decrypt and legacy bundles are offline only" do
    assert {:error, _} = Seekrit.Crypto.parse_token_key(@vectors["authToken"])
    key = @vectors["token"] |> String.split(".") |> List.last()
    legacy = @vectors["tokenId"] <> "_" <> key
    assert {:ok, _} = Seekrit.Crypto.parse_token_key(legacy)
    assert {:error, _} = Client.new(token: legacy)
  end

  test "a non-2xx surfaces the API's status and error code", context do
    body =
      JSON.encode!(%{"error" => %{"code" => "forbidden", "message" => "no key for that env"}})

    serve(context.listener, 403, body)

    assert {:error, %ApiError{status: 403, code: "forbidden"} = error} =
             Client.resolve(client!(api_url: context.api_url))

    assert Exception.message(error) == "403 forbidden: no key for that env"
  end

  test "a non-JSON error body still produces a typed error", context do
    serve(context.listener, 502, "<html>bad gateway</html>")

    assert {:error, %ApiError{status: 502, code: "internal"}} =
             Client.resolve(client!(api_url: context.api_url))
  end

  test "a connection failure is an error, not a partial result" do
    # Port 1 on loopback: nothing listens, and nothing is allowed to.
    client = client!(api_url: "http://127.0.0.1:1", connect_timeout: 1_000)
    assert {:error, %Error{}} = Client.resolve(client)
  end

  test "into_env keeps existing variables unless told otherwise", context do
    System.put_env("API_KEY", "already-set")
    on_exit(fn -> Enum.each(~w(API_KEY DATABASE_URL), &System.delete_env/1) end)

    serve(context.listener, 200, JSON.encode!(@vectors["resolve"]))
    assert {:ok, _} = Client.into_env(client!(api_url: context.api_url))
    assert System.get_env("API_KEY") == "already-set"
    assert System.get_env("DATABASE_URL") == "postgres://group/db"

    serve(context.listener, 200, JSON.encode!(@vectors["resolve"]))
    assert {:ok, _} = Client.into_env(client!(api_url: context.api_url), override: true)
    assert System.get_env("API_KEY") == "sk-app-12345"
  end

  test "a missing token is a configuration error, not a request" do
    assert {:error, %Error{message: message}} = Client.new(token: "")
    assert message =~ "SEEKRIT_TOKEN"
  end

  test "the token never reaches inspect output" do
    inspected = inspect(client!(api_url: "https://api.example.test"))
    assert inspected =~ "REDACTED"
    refute inspected =~ @vectors["token"]
  end

  test "get! falls back for an absent name but not for a failed resolve", context do
    serve(context.listener, 200, JSON.encode!(@vectors["resolve"]))
    client = client!(api_url: context.api_url)
    assert Client.get!(client, "NOT_A_SECRET", "fallback") == "fallback"

    serve(context.listener, 500, "nope")
    assert_raise ApiError, fn -> Client.get!(client, "NOT_A_SECRET", "fallback") end
  end
end
