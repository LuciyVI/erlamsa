%% Deterministic binary mutation operators used by the local core profile.
-module(erlamsa_core_bytes).
-export([mutate/4]).

mutate(Op, Input, State, Limits) when is_binary(Input), is_map(Limits) ->
    Max = maps:get(output_bytes, Limits),
    mutate_op(Op, Input, State, Limits, Max).

mutate_op(byte_flip, <<>>, _S, _L, _M) -> {skip, empty_input};
mutate_op(byte_flip, B, S0, _L, _M) ->
    {P, S1} = erlamsa_core_rng:uniform(byte_size(B), S0),
    {Bit, S2} = erlamsa_core_rng:uniform(8, S1),
    <<Head:(P-1)/binary, Byte, Tail/binary>> = B,
    {ok, <<Head/binary, (Byte bxor (1 bsl (Bit-1))), Tail/binary>>, S2,
     #{operator => byte_flip, offset => P-1, bit => Bit-1}};
mutate_op(byte_insert, B, S0, _L, Max) when byte_size(B) < Max ->
    {P, S1} = erlamsa_core_rng:uniform(byte_size(B)+1, S0),
    {Value, S2} = erlamsa_core_rng:uniform(256, S1),
    {Head, Tail} = split(B, P-1),
    {ok, <<Head/binary, (Value-1), Tail/binary>>, S2,
     #{operator => byte_insert, offset => P-1, byte => Value-1}};
mutate_op(byte_insert, _B, _S, _L, _M) -> {skip, output_limit};
mutate_op(byte_drop, <<>>, _S, _L, _M) -> {skip, empty_input};
mutate_op(byte_drop, B, S0, _L, _M) ->
    {P, S1} = erlamsa_core_rng:uniform(byte_size(B), S0),
    <<Head:(P-1)/binary, _Byte, Tail/binary>> = B,
    {ok, <<Head/binary, Tail/binary>>, S1, #{operator => byte_drop, offset => P-1}};
mutate_op(block_repeat, <<>>, _S, _L, _M) -> {skip, empty_input};
mutate_op(block_repeat, B, S0, L, Max) ->
    {P, S1} = erlamsa_core_rng:uniform(byte_size(B), S0),
    {Len0, S2} = erlamsa_core_rng:uniform(min(byte_size(B)-P+1, maps:get(block_bytes,L)), S1),
    Len = min(Len0, Max-byte_size(B)),
    case Len > 0 of
        false -> {skip, output_limit};
        true ->
            {Head, Rest} = split(B, P-1),
            <<Block:Len/binary, Tail/binary>> = Rest,
            {ok, <<Head/binary, Block/binary, Block/binary, Tail/binary>>, S2,
             #{operator => block_repeat, offset => P-1, length => Len}}
    end;
mutate_op(block_drop, <<>>, _S, _L, _M) -> {skip, empty_input};
mutate_op(block_drop, B, S0, L, _M) ->
    {P, S1} = erlamsa_core_rng:uniform(byte_size(B), S0),
    {Len, S2} = erlamsa_core_rng:uniform(min(byte_size(B)-P+1, maps:get(block_bytes,L)), S1),
    <<Head:(P-1)/binary, _Removed:Len/binary, Tail/binary>> = B,
    {ok, <<Head/binary, Tail/binary>>, S2, #{operator => block_drop, offset => P-1, length => Len}};
mutate_op(block_swap, B, S0, L, _M) when byte_size(B) >= 2 ->
    MaxLen = min(maps:get(block_bytes,L), byte_size(B) div 2),
    {Len, S1} = erlamsa_core_rng:uniform(MaxLen, S0),
    MaxPos = byte_size(B) - 2*Len + 1,
    {P, S2} = erlamsa_core_rng:uniform(MaxPos, S1),
    <<Head:(P-1)/binary, A:Len/binary, B1:Len/binary, Tail/binary>> = B,
    {ok, <<Head/binary, B1/binary, A/binary, Tail/binary>>, S2,
     #{operator => block_swap, offset => P-1, length => Len}};
mutate_op(block_swap, _B, _S, _L, _M) -> {skip, insufficient_input};
mutate_op(Op, B, S, _L, Max) when Op =:= line_repeat; Op =:= line_drop; Op =:= line_swap ->
    mutate_lines(Op, B, S, Max);
mutate_op(number, B, S, _L, _M) -> mutate_number(B, S);
mutate_op(delimiter, B, S, _L, Max) when byte_size(B) < Max ->
    Delimiters = <<" ,;:=/\\|&?%+_-()[]{}">>,
    {N, S1} = erlamsa_core_rng:uniform(byte_size(Delimiters), S),
    {P, S2} = erlamsa_core_rng:uniform(byte_size(B)+1, S1),
    <<D>> = binary:part(Delimiters, N-1, 1),
    {Head, Tail} = split(B, P-1),
    {ok, <<Head/binary, D, Tail/binary>>, S2, #{operator => delimiter, offset => P-1, byte => D}};
mutate_op(delimiter, _B, _S, _L, _M) -> {skip, output_limit};
mutate_op(unicode, B, S0, _L, Max) ->
    {P, S1} = erlamsa_core_rng:uniform(byte_size(B)+1, S0),
    {N, S2} = erlamsa_core_rng:uniform(3, S1),
    Codepoint = case N of 1 -> 16#2603; 2 -> 16#03bb; 3 -> 16#1f642 end,
    Encoded = unicode:characters_to_binary([Codepoint]),
    {Head, Tail} = split(B, P-1),
    case byte_size(B)+byte_size(Encoded) =< Max of
        true -> {ok, <<Head/binary, Encoded/binary, Tail/binary>>, S2,
                 #{operator => unicode, offset => P-1, codepoint => Codepoint}};
        false -> {skip, output_limit}
    end;
mutate_op(_, _, _, _, _) -> {skip, unsupported_operator}.

mutate_lines(Op, B, S0, Max) ->
    Lines = split_lines(B, 0, []),
    case Lines of
        [] -> {skip, no_lines};
        _ ->
            {Index, S1} = erlamsa_core_rng:uniform(length(Lines), S0),
            {Before, [Line|After]} = lists:split(Index-1, Lines),
            NewLines = case Op of
                line_drop -> Before ++ After;
                line_repeat -> Before ++ [Line,Line] ++ After;
                line_swap -> swap_lines(Index, Lines)
            end,
            Out = iolist_to_binary(NewLines),
            case {Out =/= B, byte_size(Out) =< Max} of
                {true,true} -> {ok, Out, S1, #{operator => Op, line => Index}};
                {false,_} -> {skip, no_change};
                {_,false} -> {skip, output_limit}
            end
    end.

split_lines(<<>>, _Start, Acc) -> lists:reverse(Acc);
split_lines(B, _Start, Acc) ->
    case binary:match(B, <<"\n">>) of
        {Pos,1} -> <<Line:(Pos+1)/binary, Rest/binary>> = B,
                   split_lines(Rest, 0, [Line|Acc]);
        nomatch -> lists:reverse([B|Acc])
    end.

swap_lines(_Index, Lines) when length(Lines) < 2 -> Lines;
swap_lines(Index, Lines) ->
    Other = case Index =:= length(Lines) of true -> Index-1; false -> Index+1 end,
    A = lists:nth(Index, Lines), B = lists:nth(Other, Lines),
    replace_at(Other, A, replace_at(Index, B, Lines)).

replace_at(1, Value, [_|Tail]) -> [Value|Tail];
replace_at(N, Value, [Head|Tail]) -> [Head|replace_at(N-1, Value, Tail)].

mutate_number(B, S) ->
    Runs = number_runs(B, 0, false, []),
    case Runs of
        [] -> {skip, number_not_found};
        _ ->
            {Index, S1} = erlamsa_core_rng:uniform(length(Runs), S),
            {Start, Len} = lists:nth(Index, Runs),
            <<Head:Start/binary, Num:Len/binary, Tail/binary>> = B,
            New = case Num of <<"0">> -> <<"1">>; _ -> <<Num/binary, "0">> end,
            {ok, <<Head/binary, New/binary, Tail/binary>>, S1,
             #{operator => number, offset => Start, length => Len}}
    end.

number_runs(<<>>, _Pos, {Start,Len}, Acc) -> lists:reverse([{Start,Len}|Acc]);
number_runs(<<>>, _Pos, false, Acc) -> lists:reverse(Acc);
number_runs(<<C,Rest/binary>>, Pos, false, Acc) when C >= $0, C =< $9 ->
    number_runs(Rest,Pos+1,{Pos,1},Acc);
number_runs(<<C,Rest/binary>>, Pos, {Start,Len}, Acc) when C >= $0, C =< $9 ->
    number_runs(Rest,Pos+1,{Start,Len+1},Acc);
number_runs(<<_C,Rest/binary>>, Pos, {Start,Len}, Acc) ->
    number_runs(Rest,Pos+1,false,[{Start,Len}|Acc]);
number_runs(<<_C,Rest/binary>>, Pos, false, Acc) ->
    number_runs(Rest,Pos+1,false,Acc).

split(B, N) -> {binary:part(B,0,N), binary:part(B,N,byte_size(B)-N)}.
