defmodule Seekrit.Interpolate do
  @moduledoc """
  Secret references: `${OTHER_SECRET}` inside a secret value.

  Expansion happens here, in-process, after the layers are merged — the API only
  ever holds the ciphertext of the literal `${OTHER_SECRET}` text. The rules are
  fixed by the shared golden fixture (`testdata/vectors.json`, key
  `"interpolation"`), which every seekrit client is tested against:

    * `${NAME}` becomes NAME's value from the same merged set, recursively.
    * NAME must look like an environment variable (`[A-Za-z_][A-Za-z0-9_]*`);
      anything else (`${FOO:-bar}`, `${1}`) is left exactly as written.
    * A name that is not in the set is left literal and listed in `:unresolved`,
      so a stored value containing e.g. `${GITHUB_SHA}` keeps working.
    * `$${NAME}` is an escape for the literal text `${NAME}`.
    * A reference cycle is an error.
  """

  alias Seekrit.ReferenceError

  @reference_name ~r/\A[A-Za-z_][A-Za-z0-9_]*\z/

  # Cap on a single expanded value: nested references can multiply length.
  @max_expanded_length 1_048_576

  defmodule Result do
    @moduledoc """
    The outcome of expanding a variable set.

      * `:values` — the set with every reference expanded
      * `:expanded` — names whose value had a reference expanded, sorted
      * `:unresolved` — referenced names absent from the set, sorted

    Maps are unordered in Elixir, so both lists are sorted rather than carrying
    the input's order (the other seekrit SDKs report them in input order).
    """
    defstruct values: %{}, expanded: [], unresolved: []

    @type t :: %__MODULE__{
            values: %{optional(String.t()) => String.t()},
            expanded: [String.t()],
            unresolved: [String.t()]
          }
  end

  @doc """
  Expand `${NAME}` references throughout a merged variable set.

  Returns `{:ok, %Result{}}`, or `{:error, %Seekrit.ReferenceError{}}` on a
  reference cycle or unbounded growth.

      iex> {:ok, result} =
      ...>   Seekrit.Interpolate.interpolate_secrets(%{
      ...>     "HOST" => "db.internal",
      ...>     "URL" => "postgres://app@${HOST}:5432/db"
      ...>   })
      iex> result.values["URL"]
      "postgres://app@db.internal:5432/db"
      iex> result.expanded
      ["URL"]
  """
  @spec interpolate_secrets(%{optional(String.t()) => String.t()}) ::
          {:ok, Result.t()} | {:error, ReferenceError.t()}
  def interpolate_secrets(values) when is_map(values) do
    names = values |> Map.keys() |> Enum.sort()

    initial = %{resolved: %{}, unresolved: %{}, stack: []}

    {result, state} =
      Enum.reduce(names, {%{}, initial}, fn name, {acc, st} ->
        {value, st} = resolve_name(name, values, st)
        {Map.put(acc, name, value), st}
      end)

    {:ok,
     %Result{
       values: result,
       expanded: Enum.filter(names, &(Map.fetch!(result, &1) != Map.fetch!(values, &1))),
       unresolved: state.unresolved |> Map.keys() |> Enum.sort()
     }}
  catch
    {:seekrit_reference, code, message} ->
      {:error, %ReferenceError{code: code, message: message}}
  end

  @doc """
  Like `interpolate_secrets/1`, but returns the `Result` and raises
  `Seekrit.ReferenceError` on a cycle or unbounded growth.
  """
  @spec interpolate_secrets!(%{optional(String.t()) => String.t()}) :: Result.t()
  def interpolate_secrets!(values) do
    case interpolate_secrets(values) do
      {:ok, result} -> result
      {:error, error} -> raise error
    end
  end

  # Expand one present name's value, memoized so each is expanded once.
  defp resolve_name(name, values, state) do
    case Map.fetch(state.resolved, name) do
      {:ok, cached} ->
        {cached, state}

      :error ->
        detect_cycle!(name, state.stack)
        nested = %{state | stack: [name | state.stack]}
        {out, inner} = expand(Map.fetch!(values, name), values, nested)

        if byte_size(out) > @max_expanded_length do
          throw(
            {:seekrit_reference, :too_large,
             "#{name} expands to more than #{@max_expanded_length} bytes"}
          )
        end

        {out, %{inner | stack: state.stack, resolved: Map.put(inner.resolved, name, out)}}
    end
  end

  defp detect_cycle!(name, stack) do
    ordered = Enum.reverse(stack)

    case Enum.find_index(ordered, &(&1 == name)) do
      nil ->
        :ok

      at ->
        chain = Enum.join(Enum.drop(ordered, at) ++ [name], " -> ")
        throw({:seekrit_reference, :cycle, "secret reference cycle: #{chain}"})
    end
  end

  defp expand(text, values, state) do
    Enum.reduce(scan(text), {"", state}, fn
      {nil, literal}, {out, st} ->
        {out <> literal, st}

      {reference, raw}, {out, st} ->
        if Map.has_key?(values, reference) do
          {value, st} = resolve_name(reference, values, st)
          {out <> value, st}
        else
          {out <> raw, %{st | unresolved: Map.put(st.unresolved, reference, true)}}
        end
    end)
  end

  @doc """
  Split a value into literal runs and references — the single tokenizer the
  rules above are expressed in terms of.

  Returns a list of `{reference, text}`: for a literal, `reference` is `nil`;
  for a reference, `text` is its raw `${NAME}` source (used verbatim when the
  name turns out to be absent).
  """
  @spec scan(String.t()) :: [{String.t() | nil, String.t()}]
  def scan(text) when is_binary(text), do: scan(text, [])

  defp scan(<<>>, acc), do: Enum.reverse(acc)

  defp scan(text, acc) do
    case :binary.match(text, "$") do
      :nomatch ->
        Enum.reverse([{nil, text} | acc])

      {0, 1} ->
        scan_dollar(text, acc)

      {at, 1} ->
        scan_dollar(rest_from(text, at), [{nil, binary_part(text, 0, at)} | acc])
    end
  end

  # `$${` — escape: emit a literal `${` and skip all three bytes, so the
  # `{NAME}` that follows can never be read as a reference.
  defp scan_dollar(<<"$${", rest::binary>>, acc), do: scan(rest, [{nil, "${"} | acc])

  defp scan_dollar(<<"${", rest::binary>> = text, acc) do
    with {close, 1} <- :binary.match(rest, "}"),
         name = binary_part(rest, 0, close),
         true <- Regex.match?(@reference_name, name) do
      raw = binary_part(text, 0, close + 3)
      scan(rest_from(rest, close + 1), [{name, raw} | acc])
    else
      # An unterminated `${` or a non-name: literal. Advancing a single byte
      # lets a `${` later in the run still be recognized.
      _ -> scan(rest_from(text, 1), [{nil, "$"} | acc])
    end
  end

  defp scan_dollar(<<"$", rest::binary>>, acc), do: scan(rest, [{nil, "$"} | acc])

  defp rest_from(binary, at), do: binary_part(binary, at, byte_size(binary) - at)
end
