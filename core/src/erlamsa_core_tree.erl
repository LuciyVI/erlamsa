%% Bounded, conservative parser for simple balanced SGML/XML-like tag trees.
-module(erlamsa_core_tree).
-export([check_markup/3]).

check_markup(Binary, MaxDepth, MaxNodes) when is_binary(Binary) ->
    try scan(Binary,0,[],0,MaxDepth,MaxNodes) catch _:_ -> {error,invalid_tree} end.

scan(B,Pos,Stack,Nodes,_MaxDepth,_MaxNodes) when Pos >= byte_size(B) ->
    case {Stack,Nodes} of {[],N} when N>0 -> {ok,N}; _ -> {error,invalid_tree} end;
scan(B,Pos,Stack,Nodes,MaxDepth,MaxNodes) ->
    case binary:match(B,<<"<">>,[{scope,{Pos,byte_size(B)-Pos}}]) of
        nomatch -> case {Stack,Nodes} of {[],N} when N>0->{ok,N}; _->{error,invalid_tree} end;
        {Start,1} ->
            case token(B,Start) of
                {comment,Next} -> scan(B,Next,Stack,Nodes,MaxDepth,MaxNodes);
                {open,Name,Next} -> bounded_scan(B,Next,[Name|Stack],Nodes+1,MaxDepth,MaxNodes);
                {self,Next} -> bounded_scan(B,Next,Stack,Nodes+1,MaxDepth,MaxNodes);
                {close,Name,Next} ->
                    case Stack of
                        [Name|Rest] -> scan(B,Next,Rest,Nodes,MaxDepth,MaxNodes);
                        _ -> {error,invalid_tree}
                    end;
                _ -> {error,invalid_tree}
            end
    end.

bounded_scan(B,Next,Stack,Nodes,MaxDepth,MaxNodes) ->
    case length(Stack)=<MaxDepth andalso Nodes=<MaxNodes of
        true->scan(B,Next,Stack,Nodes,MaxDepth,MaxNodes);
        false->{error,tree_limit}
    end.

token(B,Start) when Start+4=<byte_size(B) ->
    case binary:part(B,Start,4) of
        <<"<!--">> -> case binary:match(B,<<"-->">>,[{scope,{Start+4,byte_size(B)-Start-4}}]) of
            {End,3}->{comment,End+3};nomatch->error end;
        _ -> tag_token(B,Start)
    end;
token(B,Start) -> tag_token(B,Start).

tag_token(B,Start) ->
    case tag_end(B,Start+1,none) of
        error -> error;
        {End,Slash} ->
            Body=trim(binary:part(B,Start+1,End-Start-1)),
            classify(Body,Slash,End+1)
    end.

classify(<<>>,_,_) -> error;
classify(<<$!,_/binary>>,_,_) -> error;
classify(<<$?,_/binary>>,_,_) -> error;
classify(<<$/,Rest/binary>>,_,Next) ->
    case name(Rest) of {ok,Name}->{close,Name,Next};error->error end;
classify(Body,Slash,Next) ->
    case {Slash,name(Body)} of
        {slash,{ok,_Name}} -> {self,Next};
        {_,{ok,Name}} -> {open,Name,Next};
        _ -> error
    end.

name(B) ->
    Trim=trim(B),
    {Name,_Attrs}=take_name(Trim,0),
    case Name of <<>>->error;_-> {ok,lower(Name)} end.

take_name(B,Pos) when Pos<byte_size(B) ->
    C=binary:at(B,Pos),
    case name_char(C) of true->take_name(B,Pos+1);false->{binary:part(B,0,Pos),binary:part(B,Pos,byte_size(B)-Pos)} end;
take_name(B,Pos)->{binary:part(B,0,Pos),<<>>}.

name_char(C) -> (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z) orelse
                (C >= $0 andalso C =< $9) orelse lists:member(C,[$_, $-, $:, $.]).

lower(B) -> << <<(lower_char(C))>> || <<C>> <= B >>.
lower_char(C) when C >= $A, C =< $Z -> C+32;
lower_char(C) -> C.

tag_end(B,Pos,_Quote) when Pos>=byte_size(B)->error;
tag_end(B,Pos,Quote)->
    C=binary:at(B,Pos),
    case {Quote,C} of
        {none,$>} ->
            Previous=binary:at(B,Pos-1),
            {Pos,case Previous of $/->slash;_->normal end};
        {none,$"}->tag_end(B,Pos+1,$");
        {none,$'}->tag_end(B,Pos+1,$');
        {$",$"}->tag_end(B,Pos+1,none);
        {$',$'}->tag_end(B,Pos+1,none);
        _->tag_end(B,Pos+1,Quote)
    end.

trim(B) -> trim_right(trim_left(B)).
trim_left(<<C,Rest/binary>>) when C=:=32; C=:=9; C=:=10; C=:=13 -> trim_left(Rest);
trim_left(B)->B.
trim_right(B) -> trim_right(B,byte_size(B)).
trim_right(_B,0)-><<>>;
trim_right(B,N) ->
    C=binary:at(B,N-1),
    case C=:=32 orelse C=:=9 orelse C=:=10 orelse C=:=13 of
        true->trim_right(B,N-1);
        false->binary:part(B,0,N)
    end.
