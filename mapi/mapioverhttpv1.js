//Analyze MAPI over HTTP headers and payload for Exchange

//flag for exa records
var exarecords = false;

if (event == "HTTP_REQUEST"){
	//get x_header fields from Requests
	var req_headers = HTTP.headers;
	x_RequestType = req_headers['X_RequestType'];
	x_RequestID = req_headers['X_RequestID'];
	x_ClientInfo = req_headers['X_ClientInfo'];
	x_ClientApplication = req_headers['X_ClientApplication'];
	(x_RequestType)? Flow.store.x_RequestType = x_RequestType : Flow.store.x_RequestType = null;
	(x_RequestID)? Flow.store.x_RequestID = x_RequestID.split(':')[0] : Flow.store.x_RequestID = null;
	(x_ClientInfo)? Flow.store.x_ClientInfo = x_ClientInfo.split(':')[0] : Flow.store.x_ClientInfo = null;
	(x_ClientApplication)? Flow.store.x_ClientApplication = x_ClientApplication : Flow.store.x_ClientApplication = null;
	//if request is connect then extract UserDN from payload
	if (x_RequestType.indexOf('Connect') > _1){
		buf = HTTP.payload;
		data = buf.unpack('z');
		UserDN = data[0];
		if (UserDN){
			Flow.store.UserDN = UserDN;
		}		
	}
		
}

//Get x_header fields from Responses
if (event == "HTTP_RESPONSE"){
	var app = Application("MAPI");
	var connect_ErrorCode;
	var connect_ErrorCodeMsg
	x_RequestType = Flow.store.x_RequestType;
	x_RequestID = Flow.store.x_RequestID;
	x_ClientInfo = Flow.store.x_ClientInfo;
	x_ClientApplication = Flow.store.x_ClientApplication;
	connect_UserDN = Flow.store.UserDN;
	key = 'Client: ' + Flow.client.ipaddr + ' Server: ' + Flow.server.ipaddr + ' RequestType: ' + x_RequestType + ' RequestID: ' + x_RequestID;
	connect_key = 'Client: ' + Flow.client.ipaddr + ' UserDN: ' + connect_UserDN;
	
	//get x_responsecodes
	var err_code = {'0':"Success", '1':"Unknown Failure", '2':"Invalid Verb", '3':"Invalid Path", '4':"Invalid Header", '5':"Invalid Request Type", '6':"Invalid Context Cookie", '7':"Missing Header", '8':"Anonymous Not Allowed", '9':"Too Large", '10':"Context Not Found", '11':"No Privilege", '12':"Invalid Request Body", '13':"Missing Cookie", '14':"Reserved", '15':"Invalid Sequence", '16':"Endpoint Disabled", '17':"Invalid Response", '18':"Endpoint Shutting Down"};
	var resp_headers = HTTP.headers;
	x_ResponseCode = resp_headers['X_ResponseCode'];
	x_ElapsedTime = resp_headers['X_ElaspedTime'];
	if (x_ResponseCode){
		x_ResponseCodeMsg = err_code['x_ResponseCode'];
		app.metricAddDetailCount('mapi_responseCode',x_ResponseCode,1);
		app.metricAddDetailCount('mapi_responseCode_detail',key + ' Response Message: '+ x_ResponseCodeMsg,1);
		
	}
	//If this is response for connect request then extract ErrorCode from the response payload
	if (resp_headers['X_RequestType'].indexOf('Connect') > _1) {
		connect_err_code = {'80070005':"ecAccessDenied", '00000970':"ecNotEncrypted", '000004DF':"ecClientVerDisallowed", '80040111':"ecLoginFailure", '000003EB':"ecUnknownUser", '000003F2':"ecLoginPerm", '80040110':"ecVersionMismatch", '000004E1':"ecCachedModeRequired", '000004E0':"ecRpcHttpDisallowed",'000007D8':"ecProtocolDisabled"};
		buf = HTTP.payload;
		data = buf.unpack('I'+'I');
		if (data){
			connect_ErrorCode = data[1].toString();
			connect_ErrorCodeMsg = connect_err_code['connect_ErrorCode'];
			app.metricAddDetailCount('mapi_connect_errCode_count',connect_ErrorCode,1);
			app.metricAddDetailCount('mapi_connect_errCode_detail', connect_key + "ErrorCodeMsg: " + connect_ErrorCodeMsg,1);
		}
		
			
	}
	app.metricAddDetailCount('mapi_requestType',x_RequestType,1);
	app.metricAddDetailCount('mapi_clientApplication',x_ClientApplication,1);
	if (x_ElapsedTime){
		app.metricAddDetailCount('mapi_elapsedTime',key + ' Server Processing Time: ' + x_ElapsedTime,1);
	}
	//commit EXA records
	if (exarecords){
		var MAPI = HTTP.record;
		MAPI.x_RequestType = x_RequestType;
		MAPI.x_RequestID = x_RequestID;
		MAPI.x_ClientInfo = x_ClientInfo;
		MAPI.x_ClientApplication = x_ClientApplication;
		MAPI.connect_UserDN = connect_UserDN;
		MAPI.connect_ErrorCode = connect_ErrorCode;
		MAPI.connect_ErrorCodeMsg = connect_ErrorCodeMsg;
		commitRecord('MAPI',MAPI);
		
		
	}	
	
}



