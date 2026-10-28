%% Explicit SplitMix64 state. No process dictionary or VM random state.
-module(erlamsa_core_rng).
-export([seed/1, next/1, uniform/2, choose/2]).

-define(MASK, 16#ffffffffffffffff).
-define(GAMMA, 16#9e3779b97f4a7c15).

seed({A, B, C}) when is_integer(A), A >= 0, A =< ?MASK,
                     is_integer(B), B >= 0, B =< ?MASK,
                     is_integer(C), C >= 0, C =< ?MASK ->
    {((A bxor rotate(B, 21) bxor rotate(C, 42)) band ?MASK), 0}.

next({State, _Counter}) ->
    S1 = (State + ?GAMMA) band ?MASK,
    Z1 = ((S1 bxor (S1 bsr 30)) * 16#bf58476d1ce4e5b9) band ?MASK,
    Z2 = ((Z1 bxor (Z1 bsr 27)) * 16#94d049bb133111eb) band ?MASK,
    {(Z2 bxor (Z2 bsr 31)) band ?MASK, {S1, 0}}.

uniform(N, State) when is_integer(N), N > 0 ->
    {Value, NextState} = next(State),
    {(Value rem N) + 1, NextState}.

choose(List, State) when is_list(List), List =/= [] ->
    {Index, NextState} = uniform(length(List), State),
    {lists:nth(Index, List), NextState}.

rotate(Value, Bits) -> ((Value bsl Bits) bor (Value bsr (64 - Bits))) band ?MASK.
