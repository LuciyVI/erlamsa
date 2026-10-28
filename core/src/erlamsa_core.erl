%% Pure, request-scoped entrypoint. This module starts no OTP application.
-module(erlamsa_core).
-export([versions/0, prepare/2, mutate/3]).

-define(VERSIONS, #{api => 1, library => <<"0.1.0">>, rng => <<"splitmix64-v1">>,
                    catalogue => 1, patterns => 1, limits => 1}).
-define(MAX_BYTES, 1048576).

versions() -> ?VERSIONS.

prepare(Options0, Limits0) when is_map(Options0), is_map(Limits0) ->
    try
        Options = normalize_options(Options0),
        Limits = normalize_limits(Limits0),
        Identity = crypto:hash(sha256, term_to_binary({Options, Limits}, [deterministic])),
        {ok, #{core_context => 1, options => Options, limits => Limits,
               versions => ?VERSIONS, config_identity => Identity}}
    catch throw:Reason -> {error, Reason}; error:_ -> {error, invalid_options}
    end;
prepare(_, _) -> {error, invalid_options}.

mutate(Input, Request, #{core_context := 1, options := Options,
                         limits := Limits, versions := Versions})
  when is_binary(Input), is_map(Request) ->
    case Versions =:= ?VERSIONS of
        false -> {error, version_mismatch};
        true -> case valid_request(Input, Request, Limits) of
            ok -> try run_request(Input, Request, Options, Limits)
                  catch _:_ -> {error, provider_failure} end;
            {error, Reason} -> {error, Reason};
            {skip, Reason} -> {skip, Reason}
        end
    end;
mutate(_, _, _) -> {error, invalid_context}.

run_request(Input, Request, Options, Limits) ->
    Seed = maps:get(seed, Request),
    R0 = erlamsa_core_rng:seed(Seed),
    {Operator, R1} = select_operator(maps:get(operator, Request, auto), Options, R0),
    case lists:keymember(Operator, 1, maps:get(operators, Options)) of
        false -> {error, disabled_operator};
        true -> run_selected(Input, Request, Options, Limits, Seed, Operator, R1)
    end.

run_selected(Input, Request, Options, Limits, Seed, Operator, R1) ->
    {Pattern, R2} = select_pattern(maps:get(pattern, Request, auto), Options, R1),
    Strategy0 = maps:get(strategy, Request, auto),
    {Strategy, R3} = select_strategy(Strategy0, maps:get(strategy, Options), R2),
    Budget0 = min(maps:get(budget, Request, maps:get(operations, Limits)),
                  maps:get(operations, Limits)),
    Cost = operation_cost(Operator),
    Budget = Budget0 div Cost,
    case Pattern of
        skip -> {skip, pattern_skip};
        _ when Budget=:=0 -> {skip, operation_budget};
        _ ->
            {Repetitions, R4} = repetition_count(Pattern, Budget,
                                                  maps:get(repeats, Limits), R3),
            case Repetitions of
                0 -> {skip, pattern_skip};
                _ -> apply_repetitions(Input, Operator, Pattern, Strategy, Seed,
                                       Options, Limits, Repetitions, Cost, R4, [])
            end
    end.

apply_repetitions(Input, Op, Pattern, Strategy, Seed, Options, Limits, Left, Cost, Rng0, Trace) ->
    case apply_operator(Op, Input, Rng0, Strategy, Options, Limits) of
        {ok, Candidate, Rng1, Detail} when Candidate =/= Input ->
            Step = Detail,
            case Left of
                1 -> {ok, Candidate, #{operator => Op, pattern => Pattern,
                    strategy => Strategy, seed => Seed, operations_used => Cost*length(Trace)+Cost,
                    steps => lists:reverse([Step|Trace])}};
                _ -> apply_repetitions(Candidate, Op, Pattern, Strategy, Seed,
                    Options, Limits, Left-1, Cost, Rng1, [Step|Trace])
            end;
        {ok, _Candidate, _Rng1, _Detail} -> {skip, no_change};
        {skip, Reason} -> {skip, Reason}
    end.

apply_operator(Op, Input, Rng, Strategy, Options, Limits) ->
    erlamsa_core_ops:apply(Op, Input, Rng, Strategy, Options, Limits).

operation_cost(Op) when Op=:=base64;Op=:=gzip;Op=:=zlib;Op=:=zip;
                        Op=:=length;Op=:=xor8;Op=:=crc32 -> 2;
operation_cost(_) -> 1.

select_operator(auto, Options, Rng) -> weighted(maps:get(operators, Options), Rng);
select_operator(Op, _Options, Rng) -> {Op, Rng}.

select_pattern(auto, Options, Rng) -> weighted(maps:get(patterns, Options), Rng);
select_pattern(Pattern, _Options, Rng) when is_atom(Pattern) -> {Pattern, Rng};
select_pattern(Patterns, _Options, Rng) when is_list(Patterns) -> {Patterns,Rng}.

select_strategy(auto, Strategy, Rng) -> select_strategy(Strategy, Strategy, Rng);
select_strategy(mixed, _Configured, Rng) ->
    {N, Next} = erlamsa_core_rng:uniform(2, Rng),
    {case N of 1 -> preserve; _ -> perturb end, Next};
select_strategy(preserve, _Configured, Rng) -> {preserve, Rng};
select_strategy(perturb, _Configured, Rng) -> {perturb, Rng}.

repetition_count(Patterns, Budget, Max, Rng) when is_list(Patterns) ->
    case lists:member(skip,Patterns) of
        true -> {0,Rng};
        false -> pattern_count_list(Patterns,Budget,Max,Rng,0)
    end;
repetition_count(once, _Budget, _Max, Rng) -> {1, Rng};
repetition_count(skip, _Budget, _Max, Rng) -> {0, Rng};
repetition_count(many, Budget, Max, Rng) ->
    {N, Next} = erlamsa_core_rng:uniform(max(1, Max-1), Rng),
    {min(Budget, min(Max, 1+N)), Next};
repetition_count(burst, Budget, Max, Rng) ->
    {N, Next} = erlamsa_core_rng:uniform(Max, Rng),
    {min(Budget, N), Next};
repetition_count(_, _, _, Rng) -> {0, Rng}.

pattern_count_list([], _Budget, _Max, Rng, Count) -> {Count,Rng};
pattern_count_list(_Patterns, 0, _Max, Rng, Count) -> {Count,Rng};
pattern_count_list(_Patterns, _Budget, 0, Rng, Count) -> {Count,Rng};
pattern_count_list([Pattern|Rest], Budget, Max, Rng, Count) ->
    {N,Next}=repetition_count(Pattern,min(Budget,Max),min(Budget,Max),Rng),
    pattern_count_list(Rest,Budget-N,Max-N,Next,Count+N).

weighted(Weights, Rng) ->
    Total = lists:sum([W || {_Name, W} <- Weights]),
    {N, Next} = erlamsa_core_rng:uniform(Total, Rng),
    {weighted_pick(N, Weights), Next}.

weighted_pick(N, [{Name, Weight}|_]) when N =< Weight -> Name;
weighted_pick(N, [{_Name, Weight}|Rest]) -> weighted_pick(N-Weight, Rest).

valid_request(Input, Request, Limits) ->
    try
        true = byte_size(Input) =< maps:get(input_bytes, Limits),
        true = maps:keys(Request) -- [seed, operator, pattern, strategy, budget] =:= [],
        Seed = maps:get(seed, Request),
        true = valid_seed(Seed),
        Op = maps:get(operator, Request, auto),
        true = Op =:= auto orelse lists:member(Op, operator_names()),
        Pattern = maps:get(pattern, Request, auto),
        true = valid_pattern(Pattern),
        Strategy = maps:get(strategy, Request, auto),
        true = lists:member(Strategy, [auto, preserve, perturb, mixed]),
        Budget = maps:get(budget, Request, maps:get(operations, Limits)),
        true = is_integer(Budget) andalso Budget > 0 andalso Budget =< maps:get(operations, Limits),
        ok
    catch _:_ ->
        case byte_size(Input) > maps:get(input_bytes, Limits) of
            true -> {skip, input_limit}; false -> {error, invalid_request}
        end
    end.

normalize_options(Options) ->
    allowed_keys(Options, [profile, strategy, operators, patterns, inner_operator,
       length_field, xor8_field, crc32_field, field_operator]),
    Profile = maps:get(profile, Options, balanced),
    ProfileNames = profile(Profile),
    OperatorWeights = normalize_weights(maps:get(operators, Options,
        [{Name,1} || Name <- ProfileNames]), operator_names()),
    PatternWeights = normalize_weights(maps:get(patterns, Options,
        [{once,1},{many,1},{burst,1},{skip,0}]), [once,many,burst,skip]),
    Strategy = maps:get(strategy, Options, preserve),
    true = lists:member(Strategy, [preserve,perturb,mixed]),
    Inner = maps:get(inner_operator, Options, byte_flip),
    true = lists:member(Inner, [auto,byte_flip,byte_insert,byte_drop,block_repeat,
                                block_drop,block_swap,number,delimiter]),
    FieldOperator = maps:get(field_operator,Options,byte_flip),
    true = lists:member(FieldOperator,[byte_flip,byte_insert,byte_drop,block_repeat,
        block_drop,block_swap,number,delimiter,unicode]),
    FieldKeys = [length_field,xor8_field,crc32_field],
    lists:foreach(fun(K) -> case maps:find(K, Options) of
        error -> ok;
        {ok, undefined} -> ok;
        {ok, Spec} -> true = valid_field(Spec)
    end end, FieldKeys),
    #{profile => Profile, strategy => Strategy, operators => OperatorWeights,
      patterns => PatternWeights, inner_operator => Inner,
      field_operator => FieldOperator,
      length_field => maps:get(length_field, Options, undefined),
      xor8_field => maps:get(xor8_field, Options, undefined),
      crc32_field => maps:get(crc32_field, Options, undefined)}.

normalize_limits(Limits) ->
    Defaults = #{input_bytes => ?MAX_BYTES, output_bytes => ?MAX_BYTES,
        intermediate_bytes => ?MAX_BYTES, depth => 4, nodes => 1024, entries => 16,
        entry_bytes => 16384, unpacked_bytes => 65536, expansion_ratio => 32,
        operations => 8, repeats => 4, block_bytes => 128},
    allowed_keys(Limits, maps:keys(Defaults)),
    Normal = maps:merge(Defaults, Limits),
    maps:foreach(fun(Key, Value) ->
        Max = case Key of depth -> 16; nodes -> 8192; entries -> 256;
            expansion_ratio -> 1024; operations -> 64; repeats -> 16; _ -> ?MAX_BYTES end,
        true = is_integer(Value) andalso Value > 0 andalso Value =< Max
    end, Normal),
    true = maps:get(output_bytes, Normal) =< maps:get(intermediate_bytes, Normal),
    Normal.

normalize_weights(List, Allowed) when is_list(List), List =/= [] ->
    Names = [N || {N,_} <- List],
    true = length(Names) =:= length(List),
    true = length(Names) =:= length(lists:usort(Names)),
    true = lists:all(fun({N,W}) -> lists:member(N, Allowed) andalso
        is_integer(W) andalso W >= 0 andalso W =< 1000000 end, List),
    true = lists:sum([W || {_N,W} <- List]) > 0,
    Sorted = lists:keysort(1, List),
    [Pair || Pair={_N,W} <- Sorted, W > 0];
normalize_weights(_, _) -> throw(invalid_weights).

profile(bytes) -> [byte_flip,byte_insert,byte_drop,block_repeat,block_drop,
                   block_swap,line_repeat,line_drop,line_swap,number,delimiter,unicode];
profile(formats) -> [json,sgml,base64,gzip,zlib,zip];
profile(fields) -> [length,xor8,crc32];
profile(balanced) -> operator_names();
profile(_) -> throw(unknown_profile).

operator_names() -> [byte_flip,byte_insert,byte_drop,block_repeat,block_drop,block_swap,
    line_repeat,line_drop,line_swap,number,delimiter,unicode,json,sgml,base64,gzip,zlib,
    zip,length,xor8,crc32].

valid_seed({A,B,C}) -> lists:all(fun(N) -> is_integer(N) andalso N >= 0 andalso
    N =< 16#ffffffffffffffff end, [A,B,C]);
valid_seed(_) -> false.
valid_pattern(auto) -> true;
valid_pattern(P) when is_atom(P) -> lists:member(P,[once,many,burst,skip]);
valid_pattern(P) when is_list(P), P =/= [], length(P) =< 4 ->
    lists:all(fun(N) -> lists:member(N,[once,many,burst,skip]) end,P);
valid_pattern(_) -> false.
valid_field(#{offset := O, width := W, endian := E, payload_offset := P,
              payload_length := L} = M) -> map_size(M) =:= 5 andalso
    is_integer(O) andalso O >= 0 andalso lists:member(W,[8,16,32,64]) andalso
    lists:member(E,[big,little]) andalso is_integer(P) andalso P >= 0 andalso
    is_integer(L) andalso L >= 0;
valid_field(_) -> false.

allowed_keys(Map, Keys) ->
    case maps:keys(Map) -- Keys of [] -> ok; _ -> throw(unknown_option) end.
