%% Bounded markup walker shared by the format adapters.
-module(erlamsa_core_tree).
-export([check_markup/3]).

check_markup(Binary, MaxDepth, MaxNodes) when is_binary(Binary) ->
    try scan(Binary,0,0,0,MaxDepth,MaxNodes) catch _:_ -> {error,invalid_tree} end.

scan(B,Pos,Depth,Nodes,_MaxDepth,_MaxNodes) when Pos >= byte_size(B) ->
    case Depth of 0 when Nodes>0 -> {ok,Nodes}; _ -> {error,invalid_tree} end;
scan(B,Pos,Depth,Nodes,MaxDepth,MaxNodes) ->
    case binary:match(B,<<"<">>,[{scope,{Pos,byte_size(B)-Pos}}]) of
        nomatch -> case Depth of 0 when Nodes>0->{ok,Nodes}; _->{error,invalid_tree} end;
        {Start,1} ->
            case token(B,Start) of
                {comment,Next} -> scan(B,Next,Depth,Nodes,MaxDepth,MaxNodes);
                {open,Next} -> bounded_scan(B,Next,Depth+1,Nodes+1,MaxDepth,MaxNodes);
                {self,Next} -> bounded_scan(B,Next,Depth,Nodes+1,MaxDepth,MaxNodes);
                {close,Next} when Depth>0 -> scan(B,Next,Depth-1,Nodes,MaxDepth,MaxNodes);
                _ -> {error,invalid_tree}
            end
    end.

bounded_scan(B,Next,Depth,Nodes,MaxDepth,MaxNodes) ->
    case Depth=<MaxDepth andalso Nodes=<MaxNodes of
        true->scan(B,Next,Depth,Nodes,MaxDepth,MaxNodes);
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
        {End,Kind0} ->
            Body=binary:part(B,Start+1,End-Start-1),
            Trim=trim_left(Body),
            Kind=case Trim of
                <<"/",_/binary>> -> close;
                <<"!",_/binary>> -> invalid;
                <<"?",_/binary>> -> invalid;
                _ -> case Kind0 of slash -> self; _ -> open end
            end,
            case Trim of <<>>->error;_-> {Kind,End+1} end
    end.

tag_end(B,Pos,_Quote) when Pos>=byte_size(B)->error;
tag_end(B,Pos,Quote)->
    C=binary:at(B,Pos),
    case {Quote,C} of
        {none,$> } ->
            Previous=binary:at(B,Pos-1),
            {Pos,case Previous of $/->slash;_->normal end};
        {none,$"}->tag_end(B,Pos+1,$");
        {none,$'}->tag_end(B,Pos+1,$');
        {$",$"}->tag_end(B,Pos+1,none);
        {$',$'}->tag_end(B,Pos+1,none);
        _->tag_end(B,Pos+1,Quote)
    end.

trim_left(<<C,Rest/binary>>) when C=:=32; C=:=9; C=:=10; C=:=13 -> trim_left(Rest);
trim_left(B)->B.
