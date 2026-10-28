%% Conservative length and checksum recognition. A guess must be unique.
-module(erlamsa_core_fields).
-export([mutate/6]).

mutate(Op, Input, State0, Strategy, Options, Limits) ->
    case locate(Op, Input, Options) of
        {error, Reason} -> {skip, Reason};
        {ok, Field} -> mutate_field(Op, Input, State0, Strategy, Field, Options, Limits)
    end.

mutate_field(Op, Input, State0, Strategy, Field, Options, Limits) ->
    case ranges_valid(Field, byte_size(Input)) of
        false -> {skip, field_range_invalid};
        true ->
            {Selected, State1} = case Strategy of
                mixed -> erlamsa_core_rng:choose([preserve,perturb], State0);
                _ -> {Strategy, State0}
            end,
            {PayloadPrefix, Payload, PayloadSuffix} = split_payload(Input, Field),
            Inner = maps:get(field_operator,Options,byte_flip),
            case erlamsa_core_bytes:mutate(Inner, Payload, State1, Limits) of
                {ok, ChangedPayload, State2, Detail} ->
                    assemble(Op, Selected, Input, PayloadPrefix, ChangedPayload,
                             PayloadSuffix, Field, State2, Detail);
                {skip, Reason} -> {skip, Reason}
            end
    end.

assemble(Op, Strategy, Original, Prefix, Payload, Suffix, Field, State, Detail) ->
    OldPayloadLength = maps:get(payload_length, Field),
    NewPayloadLength = byte_size(Payload),
    Delta = NewPayloadLength - OldPayloadLength,
    FieldOffset0 = maps:get(offset, Field),
    PayloadEnd0 = maps:get(payload_offset, Field) + OldPayloadLength,
    FieldOffset = case FieldOffset0 >= PayloadEnd0 of true -> FieldOffset0+Delta; false -> FieldOffset0 end,
    WithoutField = <<Prefix/binary, Payload/binary, Suffix/binary>>,
    Width = maps:get(width, Field), Endian = maps:get(endian, Field),
    Value = case Strategy of
        preserve -> field_value(Op, Payload, Field);
        perturb -> perturb_value(read_field(Original, maps:get(offset, Field), Width, Endian), Width)
    end,
    case Value < (1 bsl Width) of
        false -> {skip, field_overflow};
        true ->
            Candidate = insert_field(WithoutField, FieldOffset, Width, Endian, Value),
            case Candidate =/= Original of
                true -> {ok, Candidate, State, #{operator => Op,
                    field => maps:without([payload_length], Field), strategy => Strategy,
                    old_payload_length => OldPayloadLength,
                    new_payload_length => NewPayloadLength, inner => Detail}};
                false -> {skip, no_change}
            end
    end.

field_value(length, Payload, _Field) -> byte_size(Payload);
field_value(xor8, Payload, _Field) -> lists:foldl(fun(Byte, Acc) -> Byte bxor Acc end, 0, binary_to_list(Payload));
field_value(crc32, Payload, _Field) -> erlang:crc32(Payload).

perturb_value(Value, Width) -> (Value+1) band ((1 bsl Width)-1).

locate(Op, Input, Options) ->
    Key = case Op of length -> length_field; xor8 -> xor8_field; crc32 -> crc32_field end,
    case maps:get(Key, Options, undefined) of
        undefined -> unique(heuristics(Op, Input));
        Spec -> case explicit_field(Spec, Input) of true -> {ok, Spec}; false -> {error, field_not_found} end
    end.

unique([]) -> {error, field_not_found};
unique([One]) -> {ok, One};
unique(_) -> {error, ambiguous_field}.

explicit_field(#{offset := O, width := W, endian := E, payload_offset := P,
                 payload_length := L}, Input) ->
    ranges_valid(#{offset=>O,width=>W,endian=>E,payload_offset=>P,payload_length=>L},byte_size(Input)).

ranges_valid(#{offset := O, width := W, payload_offset := P, payload_length := L}, Size) ->
    FieldBytes = W div 8,
    O+FieldBytes =< Size andalso P+L =< Size andalso
    (O+FieldBytes =< P orelse P+L =< O).

split_payload(Input, Field) ->
    P = maps:get(payload_offset, Field), L = maps:get(payload_length, Field),
    {binary:part(Input,0,P), binary:part(Input,P,L),
     binary:part(Input,P+L,byte_size(Input)-P-L)}.

heuristics(length, Input) ->
    Size = byte_size(Input),
    lists:append([length_at(Input, Offset, Width, Endian)
        || Offset <- lists:seq(0,min(3,Size-1)), Width <- [8,16,32,64],
           Endian <- [big,little], Offset+Width div 8 < Size]);
heuristics(xor8, Input) -> checksum_candidates(xor8,Input);
heuristics(crc32, Input) -> checksum_candidates(crc32,Input).

length_at(Input, Offset, Width, Endian) ->
    FieldBytes = Width div 8,
    PayloadOffset = Offset+FieldBytes,
    Length = byte_size(Input)-PayloadOffset,
    Value = read_field(Input,Offset,Width,Endian),
    case Length > 0 andalso Value =:= Length of
        true -> [#{offset=>Offset,width=>Width,endian=>Endian,
                   payload_offset=>PayloadOffset,payload_length=>Length}];
        false -> []
    end.

checksum_candidates(Op, Input) ->
    Width = case Op of xor8 -> 8; crc32 -> 32 end,
    FieldBytes = Width div 8, Size = byte_size(Input),
    case Size > FieldBytes of
        false -> [];
        true ->
            FieldOffset = Size-FieldBytes,
            lists:append([checksum_at(Op,Input,FieldOffset,Width,Endian,PayloadStart)
              || Endian <- [big,little], PayloadStart <- lists:seq(0,min(30,FieldOffset-1))])
    end.

checksum_at(Op, Input, Offset, Width, Endian, PayloadStart) ->
    PayloadLength = Offset-PayloadStart,
    Payload = binary:part(Input,PayloadStart,PayloadLength),
    Value = read_field(Input,Offset,Width,Endian),
    case field_value(Op,Payload,#{}) =:= Value of
        true -> [#{offset=>Offset,width=>Width,endian=>Endian,
                   payload_offset=>PayloadStart,payload_length=>PayloadLength}];
        false -> []
    end.

read_field(Binary, Offset, 8, _Endian) -> binary:at(Binary,Offset);
read_field(Binary, Offset, Width, big) ->
    Size = Width div 8, <<_:Offset/binary,Value:Width/big,_/binary>> = Binary,
    true = Size > 0, Value;
read_field(Binary, Offset, Width, little) ->
    <<_:Offset/binary,Value:Width/little,_/binary>> = Binary, Value.

insert_field(Binary, Offset, 8, _Endian, Value) ->
    <<Head:Offset/binary,_Old,Tail/binary>> = Binary, <<Head/binary,Value,Tail/binary>>;
insert_field(Binary, Offset, Width, big, Value) ->
    Size = Width div 8, <<Head:Offset/binary,_Old:Size/binary,Tail/binary>> = Binary,
    <<Head/binary,Value:Width/big,Tail/binary>>;
insert_field(Binary, Offset, Width, little, Value) ->
    Size = Width div 8, <<Head:Offset/binary,_Old:Size/binary,Tail/binary>> = Binary,
    <<Head/binary,Value:Width/little,Tail/binary>>.
