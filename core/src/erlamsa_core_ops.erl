%% Fixed operator catalogue for the isolated library profile.
-module(erlamsa_core_ops).
-export([apply/6, names/0]).

names() -> [byte_flip,byte_insert,byte_drop,block_repeat,block_drop,block_swap,
    line_repeat,line_drop,line_swap,number,delimiter,unicode,json,sgml,base64,
    gzip,zlib,zip,length,xor8,crc32].

apply(Op,Input,State,_Strategy,_Options,Limits)
  when Op=:=byte_flip;Op=:=byte_insert;Op=:=byte_drop;
       Op=:=block_repeat;Op=:=block_drop;Op=:=block_swap;
       Op=:=line_repeat;Op=:=line_drop;Op=:=line_swap;
       Op=:=number;Op=:=delimiter;Op=:=unicode ->
    erlamsa_core_bytes:mutate(Op,Input,State,Limits);
apply(Op,Input,State,Strategy,Options,Limits)
  when Op=:=length;Op=:=xor8;Op=:=crc32 ->
    erlamsa_core_fields:mutate(Op,Input,State,Strategy,Options,Limits);
apply(json,Input,State,_Strategy,_Options,Limits) ->
    erlamsa_core_json:mutate(Input,State,Limits);
apply(sgml,Input,State,_Strategy,_Options,Limits) ->
    erlamsa_core_sgml:mutate(Input,State,Limits);
apply(Op,Input,State,_Strategy,Options,Limits)
  when Op=:=base64;Op=:=gzip;Op=:=zlib;Op=:=zip ->
    erlamsa_core_pack:mutate(Op,Input,State,maps:get(inner_operator,Options),Limits);
apply(_,_,_,_,_,_) -> {skip,unsupported_operator}.
