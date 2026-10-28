%% In-memory wrapper transforms. Deflate output is drained in OTP bounded chunks.
-module(erlamsa_core_pack).
-export([mutate/5]).
-include_lib("kernel/include/file.hrl").

mutate(base64, Input, State, Inner, Limits) ->
    case decode_base64(Input) of
        {ok, Plain} -> rewrap(base64, base64, Plain, State, Inner, Limits);
        error -> {skip, invalid_base64}
    end;
mutate(gzip, Input, State, Inner, Limits) ->
    case Input of
        <<16#1f,16#8b,_/binary>> -> case inflate(Input,31,Limits) of
            {ok,Plain} -> rewrap(gzip,gzip,Plain,State,Inner,Limits);
            Error -> Error
        end;
        _ -> {skip, not_gzip}
    end;
mutate(zlib, Input, State, Inner, Limits) ->
    case zlib_header(Input) of
        true -> case inflate(Input,15,Limits) of
            {ok,Plain} -> rewrap(zlib,zlib,Plain,State,Inner,Limits);
            Error -> Error
        end;
        false -> {skip, not_zlib}
    end;
mutate(zip, Input, State, Inner, Limits) -> mutate_zip(Input,State,Inner,Limits).

rewrap(Wrapper, Encoder, Plain, State, Inner, Limits) ->
    case byte_size(Plain) =< maps:get(intermediate_bytes,Limits) of
        false -> {skip, intermediate_limit};
        true -> case mutate_inner(Inner,Plain,State,Limits) of
            {ok,Changed,Next,Detail} ->
                Encoded = encode(Encoder,Changed),
                case byte_size(Encoded) =< maps:get(output_bytes,Limits) of
                    true -> {ok,Encoded,Next,#{operator=>Wrapper,inner=>Detail,
                        unwrapped_bytes=>byte_size(Plain),wrapper=>Wrapper}};
                    false -> {skip,output_limit}
                end;
            Other -> Other
        end
    end.

decode_base64(Input) ->
    try
        Decoded=base64:decode(Input),
        case base64:encode(Decoded)=:=Input of true->{ok,Decoded};false->error end
    catch _:_ -> error end.

zlib_header(<<CMF,FLG,_/binary>>) -> (CMF band 15)=:=8 andalso ((CMF bsl 8)+FLG) rem 31=:=0;
zlib_header(_) -> false.

inflate(Input, WindowBits, Limits) ->
    Max=min(maps:get(unpacked_bytes,Limits),maps:get(intermediate_bytes,Limits)),
    RatioMax=max(1,byte_size(Input)*maps:get(expansion_ratio,Limits)),
    Bound=min(Max,RatioMax),
    Z=zlib:open(),
    try
        ok=zlib:inflateInit(Z,WindowBits),
        case inflate_loop(Z,Input,Bound,0,[]) of
            {ok,Chunks} -> ok=zlib:inflateEnd(Z), {ok,iolist_to_binary(lists:reverse(Chunks))};
            Error -> _=catch zlib:inflateEnd(Z), Error
        end
    catch _:_ -> _=catch zlib:inflateEnd(Z), {skip,invalid_compressed_data}
    after zlib:close(Z)
    end.

inflate_loop(Z,Data,Bound,Total,Chunks) ->
    case zlib:safeInflate(Z,Data) of
        {continue,Output} ->
            Chunk=iolist_to_binary(Output), NewTotal=Total+byte_size(Chunk),
            case NewTotal =< Bound of
                true -> inflate_loop(Z,<<>>,Bound,NewTotal,[Chunk|Chunks]);
                false -> {skip,unpacked_limit}
            end;
        {finished,Output} ->
            Chunk=iolist_to_binary(Output), NewTotal=Total+byte_size(Chunk),
            case NewTotal =< Bound of true->{ok,[Chunk|Chunks]};false->{skip,unpacked_limit} end;
        {need_dictionary,_Adler,_Output} -> {skip,preset_dictionary_unsupported}
    end.

mutate_inner(auto,Plain,State,Limits) -> mutate_inner(byte_flip,Plain,State,Limits);
mutate_inner(Inner,Plain,State,Limits) ->
    case erlamsa_core_bytes:mutate(Inner,Plain,State,Limits) of
        {ok,Changed,Next,Meta}->{ok,Changed,Next,Meta}; Other->Other
    end.

encode(base64,B) -> base64:encode(B);
encode(gzip,B) -> zlib:gzip(B);
encode(zlib,B) -> zlib:compress(B).

mutate_zip(Input,State,Inner,Limits) ->
    case preflight_zip(Input,Limits) of
        {ok,Entries} -> change_zip_entries(Entries,State,Inner,Limits);
        {error,Reason} -> {skip,Reason}
    end.

preflight_zip(Input,Limits) ->
    try
        {Count,DirectoryOffset,DirectorySize}=eocd(Input),
        true=Count>0 andalso Count=<maps:get(entries,Limits),
        true=DirectoryOffset+DirectorySize=<byte_size(Input),
        {Entries,End}=central_entries(Input,DirectoryOffset,Count,Limits,[],0),
        true=End=:=DirectoryOffset+DirectorySize,
        {ok,lists:keysort(1,Entries)}
    catch _:_ -> {error,zip_limits_or_format} end.

eocd(Input) ->
    Size=byte_size(Input),Start=max(0,Size-65557),
    Tail=binary:part(Input,Start,Size-Start),
    Matches=binary:matches(Tail,<<"PK",5,6>>),
    eocd_candidates(Input,Start,lists:reverse(Matches)).

eocd_candidates(_Input,_Start,[]) -> error(invalid_eocd);
eocd_candidates(Input,Start,[{Offset,4}|Rest]) ->
    Position=Start+Offset,
    case Position+22=<byte_size(Input) of
        false -> eocd_candidates(Input,Start,Rest);
        true ->
            <<_:Position/binary,16#06054b50:32/little,Disk:16/little,StartDisk:16/little,
              DiskCount:16/little,Count:16/little,DirSize:32/little,DirOffset:32/little,
              CommentLength:16/little,_/binary>>=Input,
            case Position+22+CommentLength=:=byte_size(Input) andalso
                 CommentLength=:=0 andalso
                 Disk=:=0 andalso StartDisk=:=0 andalso DiskCount=:=Count andalso
                 Count<16#ffff andalso DirSize<16#ffffffff andalso DirOffset<16#ffffffff of
                true->{Count,DirOffset,DirSize};
                false->eocd_candidates(Input,Start,Rest)
            end
    end.

central_entries(_Input,Position,0,_Limits,Acc,_Total)->{Acc,Position};
central_entries(Input,Position,Remaining,Limits,Acc,Total0) ->
    <<_:Position/binary,16#02014b50:32/little,_VersionMade:16/little,
      _VersionNeeded:16/little,Flags:16/little,Method:16/little,
      _Time:16/little,_Date:16/little,CRC:32/little,Compressed:32/little,
      Uncompressed:32/little,NameLength:16/little,ExtraLength:16/little,
      CommentLength:16/little,Disk:16/little,_Internal:16/little,_External:32/little,
      LocalOffset:32/little,_/binary>>=Input,
    true=Flags=:=0 andalso Method=:=0 andalso Disk=:=0,
    true=Compressed=:=Uncompressed andalso Compressed=/=16#ffffffff andalso
         Uncompressed=/=16#ffffffff,
    true=NameLength>0 andalso NameLength=<256 andalso ExtraLength=<4096 andalso CommentLength=<4096,
    NameStart=Position+46,
    Name=binary:part(Input,NameStart,NameLength),
    true=valid_entry_name(Name),
    Next=NameStart+NameLength+ExtraLength+CommentLength,
    true=Next=<byte_size(Input),
    true=Uncompressed=<maps:get(entry_bytes,Limits),
    true=Uncompressed=<maps:get(intermediate_bytes,Limits),
    Total=Total0+Uncompressed,
    true=Total=<maps:get(unpacked_bytes,Limits),
    true=Total=<maps:get(intermediate_bytes,Limits),
    Bytes=stored_entry(Input,LocalOffset,Flags,Method,CRC,Compressed,Uncompressed,Name),
    central_entries(Input,Next,Remaining-1,Limits,[{binary_to_list(Name),Bytes}|Acc],Total).

stored_entry(Input,Offset,Flags,Method,CRC,Compressed,Uncompressed,CentralName) ->
    <<_:Offset/binary,16#04034b50:32/little,_Needed:16/little,LocalFlags:16/little,
      LocalMethod:16/little,_Time:16/little,_Date:16/little,LocalCRC:32/little,
      LocalCompressed:32/little,LocalUncompressed:32/little,NameLength:16/little,
      ExtraLength:16/little,_/binary>>=Input,
    true=LocalFlags=:=Flags andalso LocalMethod=:=Method andalso
         LocalCRC=:=CRC andalso LocalCompressed=:=Compressed andalso
         LocalUncompressed=:=Uncompressed,
    true=NameLength=:=byte_size(CentralName) andalso ExtraLength=<4096,
    NameOffset=Offset+30,Name=binary:part(Input,NameOffset,NameLength),
    true=Name=:=CentralName,
    DataOffset=NameOffset+NameLength+ExtraLength,
    true=DataOffset+Compressed=<byte_size(Input),
    Data=binary:part(Input,DataOffset,Compressed),
    true=erlang:crc32(Data)=:=CRC,
    Data.

valid_entry_name(Name) when is_binary(Name), byte_size(Name)>0, byte_size(Name)=<256 ->
    binary:at(Name,0)=/=$/ andalso binary:at(Name,byte_size(Name)-1)=/=$/ andalso
    binary:match(Name,<<"..">>)=:=nomatch andalso binary:match(Name,<<0>>)=:=nomatch andalso
    binary:match(Name,<<"\\">>)=:=nomatch andalso
    lists:all(fun(C)->C>=33 andalso C=<126 end,binary_to_list(Name));
valid_entry_name(_) -> false.

change_zip_entries(Entries,State,Inner,Limits) ->
    case Entries of
        [] -> {skip,empty_zip};
        _ ->
            Sorted=lists:keysort(1,Entries),
            {Index,State1}=erlamsa_core_rng:uniform(length(Sorted),State),
            {Name,Payload}=lists:nth(Index,Sorted),
            case mutate_inner(Inner,Payload,State1,Limits) of
                {ok,Changed,State2,Detail} ->
                    ChangedEntries=replace_entry(Index,{Name,Changed},Sorted),
                    make_zip(ChangedEntries,State2,Detail,Limits);
                Other -> Other
            end
    end.

replace_entry(1,Value,[_|Tail])->[Value|Tail];
replace_entry(N,Value,[Head|Tail])->[Head|replace_entry(N-1,Value,Tail)].

make_zip(Entries,State,Detail,Limits) ->
    MaxOutput=maps:get(output_bytes,Limits),
    Fixed={{1980,1,1},{0,0,0}},
    Spec=[{Name,Bytes,#file_info{size=byte_size(Bytes),type=regular,
        access=read_write,mtime=Fixed,ctime=Fixed,atime=Fixed}} || {Name,Bytes}<-Entries],
    case zip:create("efz.zip",Spec,[memory,{uncompress,all}]) of
        {ok,{_Name,Archive}} when byte_size(Archive)=<MaxOutput ->
            {ok,Archive,State,#{operator=>zip,inner=>Detail,entries=>length(Entries),
                                archive_bytes=>byte_size(Archive)}};
        {ok,_} -> {skip,output_limit};
        {error,_} -> {skip,zip_rebuild_failed}
    end.
