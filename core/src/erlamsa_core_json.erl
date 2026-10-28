%% Small bounded JSON grammar walker. It edits primitive value tokens only.
-module(erlamsa_core_json).
-export([mutate/3]).

mutate(Input, State, Limits) ->
    try
        {End, Nodes, Candidates} = value(Input, skip_ws(Input,0), 0, 0, Limits),
        true = skip_ws(Input,End) =:= byte_size(Input),
        true = Nodes =< maps:get(nodes,Limits),
        case Candidates of
            [] -> {skip, no_json_value};
            _ ->
                {Index,Next} = erlamsa_core_rng:uniform(length(Candidates),State),
                {Offset,Length,Replacement} = lists:nth(Index,Candidates),
                Head = binary:part(Input,0,Offset),
                Tail = binary:part(Input,Offset+Length,byte_size(Input)-Offset-Length),
                {ok,<<Head/binary,Replacement/binary,Tail/binary>>,Next,
                 #{operator=>json,offset=>Offset,length=>Length,nodes=>Nodes}}
        end
    catch throw:invalid_json -> {skip, invalid_json};
          error:function_clause -> {skip, invalid_json};
          error:badarg -> {skip, invalid_json};
          error:{badmatch,false} -> {skip, invalid_json}
    end.

value(B, P0, Depth, Nodes0, Limits) ->
    true = Depth =< maps:get(depth,Limits),
    true = Nodes0 < maps:get(nodes,Limits),
    P = skip_ws(B,P0),
    case byte_at(B,P) of
        ${ -> object(B,P+1,Depth+1,Nodes0+1,Limits);
        $[ -> array(B,P+1,Depth+1,Nodes0+1,Limits);
        $" -> {End,_} = string(B,P+1), {End,Nodes0+1,[]};
        $t -> primitive(B,P,<<"true">>,<<"false">>,Nodes0);
        $f -> primitive(B,P,<<"false">>,<<"true">>,Nodes0);
        $n -> primitive(B,P,<<"null">>,<<"true">>,Nodes0);
        C when C =:= $-; C >= $0, C =< $9 -> number(B,P,Nodes0);
        _ -> throw(invalid_json)
    end.

object(B,P0,Depth,Nodes0,Limits) ->
    P=skip_ws(B,P0),
    case byte_at(B,P) of
        $} -> {P+1,Nodes0,[]};
        $" ->
            {KeyEnd,_}=string(B,P+1), Colon=skip_ws(B,KeyEnd),
            true=byte_at(B,Colon)=:=$:,
            {ValueEnd,Nodes1,C1}=value(B,Colon+1,Depth,Nodes0,Limits),
            object_tail(B,ValueEnd,Depth,Nodes1,Limits,C1);
        _ -> throw(invalid_json)
    end.

object_tail(B,P0,Depth,Nodes,Limits,Candidates) ->
    P=skip_ws(B,P0),
    case byte_at(B,P) of
        $, ->
            KeyStart=skip_ws(B,P+1),
            true=byte_at(B,KeyStart)=:=$",
            {KeyEnd,_}=string(B,KeyStart+1), Colon=skip_ws(B,KeyEnd),
            true=byte_at(B,Colon)=:=$:,
            {ValueEnd,Nodes1,C1}=value(B,Colon+1,Depth,Nodes,Limits),
            object_tail(B,ValueEnd,Depth,Nodes1,Limits,Candidates++C1);
        $} -> {P+1,Nodes,Candidates};
        _ -> throw(invalid_json)
    end.

array(B,P0,Depth,Nodes0,Limits) ->
    P=skip_ws(B,P0),
    case byte_at(B,P) of
        $] -> {P+1,Nodes0,[]};
        _ ->
            {ValueEnd,Nodes1,C1}=value(B,P,Depth,Nodes0,Limits),
            array_tail(B,ValueEnd,Depth,Nodes1,Limits,C1)
    end.

array_tail(B,P0,Depth,Nodes,Limits,Candidates) ->
    P=skip_ws(B,P0),
    case byte_at(B,P) of
        $, ->
            {ValueEnd,Nodes1,C1}=value(B,P+1,Depth,Nodes,Limits),
            array_tail(B,ValueEnd,Depth,Nodes1,Limits,Candidates++C1);
        $] -> {P+1,Nodes,Candidates};
        _ -> throw(invalid_json)
    end.

primitive(B,P,Token,Replacement,Nodes) ->
    case binary:part(B,P,byte_size(Token)) of
        Token -> {P+byte_size(Token),Nodes+1,[{P,byte_size(Token),Replacement}]};
        _ -> throw(invalid_json)
    end.

number(B,P,Nodes) ->
    End=number_end(B,P), Token=binary:part(B,P,End-P),
    case re:run(Token,<<"^-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?$">>,
                [{capture,none}]) of
        match -> {End,Nodes+1,[{P,byte_size(Token),case Token of <<"0">>-><<"1">>;_-><<"0">> end}]};
        _ -> throw(invalid_json)
    end.

number_end(B,P) when P < byte_size(B) ->
    C=binary:at(B,P),
    case (C >= $0 andalso C =< $9) orelse C=:=$- orelse C=:=$+ orelse
         C=:=$. orelse C=:=$e orelse C=:=$E of
        true -> number_end(B,P+1);
        false -> P
    end;
number_end(_B,P) -> P.

string(B,P) -> string(B,P,false).
string(B,P,_) when P >= byte_size(B) -> throw(invalid_json);
string(B,P,true) ->
    C=binary:at(B,P),
    case C of
        $u ->
            true=P+4<byte_size(B),
            Digits=binary:part(B,P+1,4),
            true=lists:all(fun is_hex/1,binary_to_list(Digits)),
            string(B,P+5,false);
        $" -> string(B,P+1,false);
        $\\ -> string(B,P+1,false);
        $/ -> string(B,P+1,false);
        $b -> string(B,P+1,false);
        $f -> string(B,P+1,false);
        $n -> string(B,P+1,false);
        $r -> string(B,P+1,false);
        $t -> string(B,P+1,false);
        _ -> throw(invalid_json)
    end;
string(B,P,false) ->
    case binary:at(B,P) of
        $" -> {P+1,ok};
        $\\ -> string(B,P+1,true);
        C when C < 16#20 -> throw(invalid_json);
        _ -> string(B,P+1,false)
    end.

skip_ws(B,P) when P < byte_size(B) ->
    case binary:at(B,P) of
        $  -> skip_ws(B,P+1); $\t -> skip_ws(B,P+1);
        $\r -> skip_ws(B,P+1); $\n -> skip_ws(B,P+1);
        _ -> P
    end;
skip_ws(_B,P) -> P.

byte_at(B,P) when P >= 0, P < byte_size(B) -> binary:at(B,P);
byte_at(_B,_P) -> eof.

is_hex(C) -> (C >= $0 andalso C =< $9) orelse (C >= $a andalso C =< $f) orelse
             (C >= $A andalso C =< $F).
