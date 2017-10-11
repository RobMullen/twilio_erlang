-module(twilio_util).

-export([system_time/0]).

system_time() ->
    erlang:system_time().
