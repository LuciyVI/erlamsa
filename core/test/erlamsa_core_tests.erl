-module(erlamsa_core_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

limits() -> #{input_bytes=>4096,output_bytes=>4096,intermediate_bytes=>4096,
    depth=>8,nodes=>512,entries=>16,entry_bytes=>2048,unpacked_bytes=>4096,
    expansion_ratio=>64,operations=>16,repeats=>8,block_bytes=>32}.

prepare(Options) -> {ok,Context}=erlamsa_core:prepare(Options,limits()),Context.
request(Op) -> #{seed=>{17,23,41},operator=>Op,pattern=>once,strategy=>preserve,budget=>1}.

versions_and_default_context_test() ->
    ?assertEqual(#{api=>1,library=><<"0.1.0">>,rng=><<"splitmix64-v1">>,
        catalogue=>1,patterns=>1,limits=>1},erlamsa_core:versions()),
    ?assertMatch({ok,#{core_context:=1}},erlamsa_core:prepare(#{},#{})).

binary_values_and_request_determinism_test() ->
    C=prepare(#{operators=>[{byte_flip,1}]}),
    Inputs=[<<>>,<<0>>,list_to_binary(lists:seq(0,255)),<<255,254,128,0,195,40>>],
    lists:foreach(fun(<<>>) ->
        ?assertMatch({ok,<<_,_/binary>>,_},erlamsa_core:mutate(<<>>,
            (request(byte_insert))#{operator=>byte_insert},prepare(#{operators=>[{byte_insert,1}]})));
        (Input) ->
            R=request(byte_flip),
            First=erlamsa_core:mutate(Input,R,C),
            ?assertMatch({ok,_,_},First),
            _=rand:seed(exsplus,{1,2,3}),_=rand:uniform(),
            ?assertEqual(First,erlamsa_core:mutate(Input,R,C))
    end,Inputs).

bounded_inputs_and_invalid_requests_test() ->
    L=(limits())#{input_bytes=>4,output_bytes=>4,intermediate_bytes=>4},
    C=prepare_with(#{operators=>[{byte_flip,1}]},L),
    ?assertMatch({ok,_,_},erlamsa_core:mutate(<<1,2,3,4>>,request(byte_flip),C)),
    ?assertEqual({skip,input_limit},erlamsa_core:mutate(<<1,2,3,4,5>>,request(byte_flip),C)),
    ?assertEqual({error,invalid_request},erlamsa_core:mutate(<<0>>,
        (request(byte_flip))#{unexpected=>true},C)),
    ?assertEqual({error,disabled_operator},erlamsa_core:mutate(<<0>>,
        request(byte_drop),C)),
    ?assertMatch({error,_},erlamsa_core:prepare(#{operators=>[{no_such_operator,1}]},limits())).

byte_operator_families_test() ->
    Input= <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31>>,
    Cases=[{byte_flip,Input},{byte_insert,Input},{byte_drop,Input},
        {block_repeat,Input},{block_drop,Input},{block_swap,Input},
        {line_repeat,<<"alpha\nbeta\ngamma\n">>},
        {line_drop,<<"alpha\nbeta\ngamma\n">>},
        {line_swap,<<"alpha\nbeta\ngamma\n">>},
        {number,<<"id=123;count=9">>},{delimiter,Input},{unicode,Input}],
    lists:foreach(fun({Op,B}) ->
        C=prepare(#{operators=>[{Op,1}]}),
        ?assertMatch({ok,Out,_} when Out=/=B,erlamsa_core:mutate(B,request(Op),C))
    end,Cases).

json_and_sgml_tree_mutations_test() ->
    Json= <<"{\"name\":\"fixture\",\"n\":42,\"items\":[true,null]}">>,
    JC=prepare(#{operators=>[{json,1}]}),
    {ok,ChangedJson,_}=erlamsa_core:mutate(Json,request(json),JC),
    ?assertNotEqual(Json,ChangedJson),
    ?assertMatch({ok,_,_},erlamsa_core:mutate(ChangedJson,request(json),JC)),
    Xml= <<"<root><leaf id='1'/></root>">>,
    SC=prepare(#{operators=>[{sgml,1}]}),
    {ok,ChangedXml,_}=erlamsa_core:mutate(Xml,request(sgml),SC),
    ?assertNotEqual(Xml,ChangedXml),
    ?assertMatch({ok,_},erlamsa_core_tree:check_markup(ChangedXml,8,128)).

wrappers_roundtrip_and_determinism_test() ->
    Plain= <<"local wrapped bytes",0,255>>,
    Cases=[{base64,base64:encode(Plain),fun base64:decode/1},
        {gzip,zlib:gzip(Plain),fun zlib:gunzip/1},
        {zlib,zlib:compress(Plain),fun zlib:uncompress/1}],
    lists:foreach(fun({Op,Wrapped,Decode}) ->
        C=prepare(#{operators=>[{Op,1}],inner_operator=>byte_flip}),R=(request(Op))#{budget=>2},
        FirstResult={ok,First,_}=erlamsa_core:mutate(Wrapped,R,C),
        ?assertNotEqual(Wrapped,First),
        ?assertNotEqual(Plain,Decode(First)),
        ?assertEqual(FirstResult,erlamsa_core:mutate(Wrapped,R,C))
    end,Cases).

compressed_expansion_limit_test() ->
    Bomb=zlib:gzip(binary:copy(<<$A>>,100000)),
    L=(limits())#{unpacked_bytes=>1024,intermediate_bytes=>4096,expansion_ratio=>1024},
    C=prepare_with(#{operators=>[{gzip,1}],inner_operator=>byte_flip},L),
    ?assertEqual({skip,unpacked_limit},erlamsa_core:mutate(Bomb,(request(gzip))#{budget=>2},C)).

zip_in_memory_roundtrip_test() ->
    Plain= <<"zip payload",0,255>>,
    {ok,{_Name,Archive}}=zip:create("fixture.zip",[{"msg.bin",Plain}],
                                    [memory,{uncompress,all}]),
    C=prepare(#{operators=>[{zip,1}],inner_operator=>byte_flip}),R=(request(zip))#{budget=>2},
    {ok,Changed,_}=erlamsa_core:mutate(Archive,R,C),
    ?assertNotEqual(Archive,Changed),
    ?assertEqual(erlamsa_core:mutate(Archive,R,C),erlamsa_core:mutate(Archive,R,C)),
    {ok,[{"msg.bin",Inner}]}=zip:unzip(Changed,[memory]),
    ?assertNotEqual(Plain,Inner).

length_preserve_and_perturb_test() ->
    Input= <<0,4,"abcd">>,
    Field=#{offset=>0,width=>16,endian=>big,payload_offset=>2,payload_length=>4},
    C=prepare(#{operators=>[{length,1}],length_field=>Field,field_operator=>byte_insert}),
    {ok,Preserved,Meta}=erlamsa_core:mutate(Input,(request(length))#{budget=>2},C),
    ?assertEqual(5,binary:decode_unsigned(binary:part(Preserved,0,2),big)),
    ?assertEqual(preserve,maps:get(strategy,hd(maps:get(steps,Meta)))),
    {ok,Perturbed,_}=erlamsa_core:mutate(Input,(request(length))#{strategy=>perturb,budget=>2},C),
    ?assertEqual(5,binary:decode_unsigned(binary:part(Perturbed,0,2),big)).

checksum_preserve_and_perturb_test() ->
    Payload= <<1,2,3>>, Xor=lists:foldl(fun(B,A)->B bxor A end,0,binary_to_list(Payload)),
    XInput= <<"HD",Payload/binary,Xor>>,
    XField=#{offset=>5,width=>8,endian=>big,payload_offset=>2,payload_length=>3},
    XC=prepare(#{operators=>[{xor8,1}],xor8_field=>XField}),
    {ok,XOut,_}=erlamsa_core:mutate(XInput,(request(xor8))#{budget=>2},XC),
    XNewPayload=binary:part(XOut,2,3),
    ?assertEqual(lists:foldl(fun(B,A)->B bxor A end,0,binary_to_list(XNewPayload)),binary:at(XOut,5)),
    CRC=erlang:crc32(Payload),CInput= <<"HD",Payload/binary,CRC:32/big>>,
    CField=#{offset=>5,width=>32,endian=>big,payload_offset=>2,payload_length=>3},
    CC=prepare(#{operators=>[{crc32,1}],crc32_field=>CField}),
    {ok,COut,_}=erlamsa_core:mutate(CInput,(request(crc32))#{budget=>2},CC),
    CNewPayload=binary:part(COut,2,3),
    ?assertEqual(erlang:crc32(CNewPayload),binary:decode_unsigned(binary:part(COut,5,4),big)),
    {ok,XPerturbed,_}=erlamsa_core:mutate(XInput,(request(xor8))#{strategy=>perturb,budget=>2},XC),
    ?assertNotEqual(lists:foldl(fun(B,A)->B bxor A end,0,binary_to_list(binary:part(XPerturbed,2,3))),
                    binary:at(XPerturbed,5)).

weight_and_strategy_validation_test() ->
    ?assertMatch({error,_},erlamsa_core:prepare(#{operators=>[{byte_flip,-1}]},limits())),
    ?assertMatch({error,_},erlamsa_core:prepare(#{patterns=>[{once,0}]},limits())),
    ?assertMatch({error,_},erlamsa_core:prepare(#{operators=>[{byte_flip,1},{byte_flip,2}]},limits())),
    ?assertMatch({error,_},erlamsa_core:prepare(#{strategy=>unknown},limits())).

prepare_with(Options,Limits) -> {ok,C}=erlamsa_core:prepare(Options,Limits),C.
