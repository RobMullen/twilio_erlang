%%%-------------------------------------------------------------------
%%% @author Ryan Huffman <ryanhuffman@gmail.com>
%%% @copyright 2012, Ryan Huffman
%%% @doc Really basic implementation of JSON Web Tokens as specified at
%%% http://self-issued.info/docs/draft-jones-json-web-token.html
%%% Only implements JWS tokens for Twilio Capabilities usage.  If
%%% completed, this should be pulled out into a standalone application.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(twilio_jsonjwt).

-export([encode/3,
         encode/4]).

-include("twilio.hrl").

%% @doc Encodes a JWT.  Algorithm should be "HS256" or "none".
-spec encode(list(claim()), string(), crypto_algorithm())-> binary().
encode(Claims, Key, Algorithm) ->
    encode(Claims, Key, Algorithm, []).

-spec encode([claim()], string(), crypto_algorithm(), list())-> binary().
encode(Claims, Key, Algorithm, ExtraHeaders) ->
    Header = [{<<"typ">>, <<"JWT">>}, {<<"alg">>, list_to_binary(Algorithm)} | ExtraHeaders],
    HeaderJSON = unicode:characters_to_binary(mochijson2:encode({struct, Header}), utf8),
    HeaderEncoded = base64:encode(HeaderJSON),

    MessageJSON = unicode:characters_to_binary(mochijson2:encode({struct, Claims}), utf8),
    MessageEncoded = base64:encode(MessageJSON),

    SigningInput = <<HeaderEncoded/binary, ".", MessageEncoded/binary>>,
    Signature = sign(Algorithm, Key, SigningInput),

    SignatureEncoded = base64:encode(Signature),
    <<HeaderEncoded/binary, ".", MessageEncoded/binary, ".", SignatureEncoded/binary>>.

sign("none", _Key, _Data) ->
    <<"">>;
sign("HS256", Key, Data) ->
    crypto:hmac(sha256, Key, Data);
sign("HS384", Key, Data) ->
    crypto:hmac(sha384, Key, Data);
sign("HS512", Key, Data) ->
    crypto:hmac(sha512, Key, Data);
sign(_Algorithm, _Key, _Data) ->
    throw(unsupported_algorithm).
