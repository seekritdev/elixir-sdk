defmodule Seekrit.MixProject do
  use Mix.Project

  @version "0.3.0"
  @source_url "https://github.com/seekritdev/elixir-sdk"

  def project do
    [
      app: :seekrit,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      name: "seekrit",
      source_url: @source_url,
      docs: docs()
    ]
  end

  # `:inets` and `:ssl` are declared so they are on the code path and in any
  # release that depends on this one — Mix prunes the load path to declared
  # applications, and without them `:httpc` fails at its first call with
  # `:http_util` undefined. Seekrit.Client *also* starts them itself, because
  # config/runtime.exs runs before any application has been started.
  def application do
    [extra_applications: [:crypto, :public_key, :inets, :ssl]]
  end

  defp deps do
    [{:ex_doc, "~> 0.34", only: :dev, runtime: false}]
  end

  defp description do
    """
    Read-path SDK for seekrit, the zero-knowledge secrets manager. Authenticate
    with a service token, resolve your environment, and get decrypted secrets —
    the API only ever returns ciphertext; decryption happens in your process.
    No runtime dependencies.
    """
  end

  defp package do
    [
      licenses: ["MIT"],
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE .formatter.exs),
      links: %{
        "Website" => "https://seekrit.dev",
        "Documentation" => "https://seekrit.dev/docs/guides/sdks",
        "AI agents" => "https://seekrit.dev/docs/guides/ai-agents",
        "Security model" => "https://seekrit.dev/docs/concepts/security",
        "GitHub" => @source_url
      }
    ]
  end

  defp docs do
    [
      main: "Seekrit",
      source_ref: "v#{@version}",
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end
end
