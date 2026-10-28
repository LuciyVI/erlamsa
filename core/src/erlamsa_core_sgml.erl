%% A limited SGML/XML-like tree mutation: insert a comment into a balanced tree.
-module(erlamsa_core_sgml).
-export([mutate/3]).

mutate(Input, State, Limits) ->
    case erlamsa_core_tree:check_markup(Input,maps:get(depth,Limits),maps:get(nodes,Limits)) of
        {ok,Nodes} -> insert_comment(Input,State,Limits,Nodes);
        {error,tree_limit} -> {skip,tree_limit};
        _ -> {skip,invalid_sgml}
    end.

insert_comment(Input,State,Limits,Nodes) ->
    case opening_tag_end(Input) of
        {ok,Offset} ->
            Comment = <<"<!--efz-->">>,
            Candidate = <<(binary:part(Input,0,Offset))/binary,Comment/binary,
                          (binary:part(Input,Offset,byte_size(Input)-Offset))/binary>>,
            case byte_size(Candidate)=<maps:get(output_bytes,Limits) of
                true->{ok,Candidate,State,#{operator=>sgml,operation=>comment_insert,nodes=>Nodes}};
                false->{skip,output_limit}
            end;
        error->{skip,no_sgml_element}
    end.

opening_tag_end(Input) ->
    case binary:match(Input,<<"<">>) of
        {Start,1} when Start+1<byte_size(Input) ->
            case binary:at(Input,Start+1) of
                C when C=:=$/; C=:=$!; C=:=$? -> error;
                _ -> case binary:match(Input,<<">">>,[{scope,{Start+1,byte_size(Input)-Start-1}}]) of
                    {End,1} -> case Input of
                        <<_:End/binary,$>,_/binary>> -> {ok,End+1};
                        _ -> error
                    end;
                    nomatch -> error
                end
            end;
        _ -> error
    end.
