# Resolve and print the names (never the values) a service token can see.
#
#   SEEKRIT_TOKEN=skt_… mix run examples/basic.exs
#
# Against a local API, point it somewhere else:
#
#   SEEKRIT_API_URL=http://127.0.0.1:8787 SEEKRIT_TOKEN=skt_… mix run examples/basic.exs

case Seekrit.resolve() do
  {:ok, secrets} ->
    IO.puts("resolved #{map_size(secrets)} secrets:")

    secrets
    |> Map.keys()
    |> Enum.sort()
    |> Enum.each(fn name ->
      IO.puts("  #{name} (#{byte_size(Map.fetch!(secrets, name))} bytes)")
    end)

  {:error, %Seekrit.ApiError{status: status, code: code} = error} ->
    IO.puts(:stderr, "API refused the resolve (#{status} #{code}): #{Exception.message(error)}")
    System.halt(1)

  {:error, error} ->
    IO.puts(:stderr, "resolve failed: #{Exception.message(error)}")
    System.halt(1)
end
