-module(erljwt).
-export([verify_token/2]).
-export([base64pad/1]).

verify_token(Token, Jwks) ->
	{Header_b64,Payload_b64,Signature_b64} = split_token(Token),

	{Jwks_json} = jiffy:decode(Jwks),

	Keys = proplists:get_value(<<"keys">>, Jwks_json),

	verify_signature({Header_b64,Payload_b64,Signature_b64},Keys).



verify_signature({Header_b64,Payload_b64,Signature_b64},Key) ->
	io:format("starting verify~n"),
	verify_signature({Header_b64,Payload_b64,Signature_b64},[],Key).
	
verify_signature({_,_,_},VerifiedTokens,[]) ->
	io:format("finished verify~n"),
		VerifiedTokens;
verify_signature({Header_b64,Payload_b64,Signature_b64},VerifiedTokens,[{Key}|Tail]) ->

	io:format("verify key[~p]~n",[Key]),
	{_Header_json,Payload_json,_Signature_json} = decode_token({Header_b64,Payload_b64,Signature_b64}),

	E_b64 = proplists:get_value(<<"e">>,Key),
	N_b64 = proplists:get_value(<<"n">>,Key),

	E = base64:decode(base64pad(E_b64)),
	N = base64:decode(base64pad(N_b64)),

	Msg = <<Header_b64/binary,<<".">>/binary,Payload_b64/binary>>,
	Signature = base64:decode(base64pad(Signature_b64)),

	Valid = crypto:verify(rsa,sha256,Msg,Signature,[E,N]),
	io:format("Valid[~p]~n",[Valid]),

	VT = [[{<<"valid">>,Valid},{<<"payload">>,Payload_json}]] ++ VerifiedTokens,
	verify_signature({Header_b64,Payload_b64,Signature_b64},VT,Tail).


split_token(Token) ->
	% JWT token format is
	% Header.Payload.Signature
	% elements are delimited by period (.)
	% Header and Payload are JSON encoded in base64 
	% Signature is the cryptographic signature of Header.Payload

	[Header_b64, Tail] = binary:split(Token, <<".">>),
	[Payload_b64, Signature_b64] = binary:split(Tail, <<".">>),
	{Header_b64,Payload_b64,Signature_b64}.

decode_token({Header_b64,Payload_b64,Signature_b64}) ->
	Header = base64:decode(base64pad(Header_b64)),
	Payload = base64:decode(base64pad(Payload_b64)),
	Signature = base64:decode(base64pad(Signature_b64)),

	{Header,Payload,Signature}.

base64pad(Raw_data) ->

	Data = << <<(convert_char(Digit)) >> || << Digit>> <= Raw_data >>,

	case byte_size(Data) rem 4 of 
		3 -> <<Data/binary,<<"=">>/binary>>;
		2 -> <<Data/binary,<<"==">>/binary>>;
		_ -> Data
	end.

convert_char($_) -> $/;
convert_char($-) -> $+;
convert_char(D) -> D.
