defmodule Seekrit do
  @moduledoc """
  Read-path SDK for [seekrit](https://seekrit.dev), the zero-knowledge secrets
  manager.

  Authenticate with a service token, resolve your environment, and get
  **decrypted** secrets — `GET /v1/resolve` only ever returns ciphertext plus a
  data key wrapped to your token's public key, and this library is the piece
  that turns that into plaintext, in your own process.

      secrets = Seekrit.resolve!()
      secrets["DATABASE_URL"]

  For a long-lived client (a connection reused across calls, or a non-default
  environment slice), build one with `Seekrit.Client.new/1`.

  ## In a release

  `config/runtime.exs` runs before your applications start, which is the right
  place to pull secrets in — `into_env!/1` starts `:inets` and `:ssl` itself, so
  it works there:

      # config/runtime.exs
      if config_env() == :prod do
        Seekrit.load_env!()

        config :my_app, MyApp.Repo, url: System.fetch_env!("DATABASE_URL")
      end

  ## Errors

  Elixir exceptions have no hierarchy, so the bang functions can raise any of
  four types: `Seekrit.Error` (configuration and transport), `Seekrit.ApiError`
  (non-2xx, carrying `:status` and `:code`), `Seekrit.CryptoError`, and
  `Seekrit.ReferenceError`. Every non-bang function returns them as
  `{:error, exception}` instead.

  Everything is **fail-closed**: a bad token, an unreachable API, or a layer
  that will not decrypt is an error, never a partial result.
  """

  alias Seekrit.Client

  @type secrets :: Client.secrets()

  @doc """
  Resolve with a one-off client. Takes the same options as `Seekrit.Client.new/1`.
  """
  @spec resolve(keyword()) :: {:ok, secrets()} | {:error, Exception.t()}
  def resolve(opts \\ []) do
    with {:ok, client} <- Client.new(opts), do: Client.resolve(client)
  end

  @doc """
  Like `resolve/1`, but raises instead of returning `{:error, exception}`.
  """
  @spec resolve!(keyword()) :: secrets()
  def resolve!(opts \\ []), do: opts |> Client.new!() |> Client.resolve!()

  @doc """
  Resolve and load every secret into the OS environment with `System.put_env/2`.

  Existing variables are kept unless `override: true`. Returns the resolved
  secrets. Takes the same options as `Seekrit.Client.new/1`.

      Seekrit.load_env!()
      System.fetch_env!("DATABASE_URL")
  """
  @spec load_env!(keyword()) :: secrets()
  def load_env!(opts \\ []) do
    {override, opts} = Keyword.pop(opts, :override, false)
    opts |> Client.new!() |> Client.into_env!(override: override)
  end
end
