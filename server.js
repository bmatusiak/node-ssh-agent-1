var net = require('net');
var parse = require('through-parse');
var split = require('split');

var ctype = require('ctype');

var BANNER = { type: 'bannerResponse', version: 1.0, name: 'SSHAgent' };


/*
    SSH_AGENTC_REQUEST_IDENTITIES                  11
    SSH_AGENTC_SIGN_REQUEST                        13
    SSH_AGENTC_ADD_IDENTITY                        17
    SSH_AGENTC_REMOVE_IDENTITY                     18
    SSH_AGENTC_REMOVE_ALL_IDENTITIES               19
    SSH_AGENTC_ADD_ID_CONSTRAINED                  25
    SSH_AGENTC_ADD_SMARTCARD_KEY                   20
    SSH_AGENTC_REMOVE_SMARTCARD_KEY                21
    SSH_AGENTC_LOCK                                22
    SSH_AGENTC_UNLOCK                              23
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED       26
    SSH_AGENTC_EXTENSION                           27
    
    The following numbers are used for replies from the agent to the client.

    SSH_AGENT_FAILURE                               5
    SSH_AGENT_SUCCESS                               6
    SSH_AGENT_EXTENSION_FAILURE                     28
    SSH_AGENT_IDENTITIES_ANSWER                     12
    SSH_AGENT_SIGN_RESPONSE                         14
    
    The following numbers are used to identify key constraints. These are only used in key constraints and are not sent as message numbers.
    
    SSH_AGENT_CONSTRAIN_LIFETIME                    1
    SSH_AGENT_CONSTRAIN_CONFIRM                     2
    SSH_AGENT_CONSTRAIN_EXTENSION                   3
    
    The following numbers may be present in signature request (SSH_AGENTC_SIGN_REQUEST) messages. These flags form a bit field by taking the logical OR of zero or more flags.

    SSH_AGENT_RSA_SHA2_256                          2
    SSH_AGENT_RSA_SHA2_512                          4
*/

var PROTOCOL = {
  SSH_AGENTC_REQUEST_RSA_IDENTITIES: 11,
  SSH_AGENT_IDENTITIES_ANSWER: 12,
  SSH2_AGENTC_SIGN_REQUEST: 13,
  SSH2_AGENT_SIGN_RESPONSE: 14,
  SSH_AGENT_FAILURE: 5,
  SSH_AGENT_SUCCESS: 6
};


function _writeString(request, buffer, offset) {
  // assert.ok(request);
  // assert.ok(buffer);
  // assert.ok(offset !== undefined);

  ctype.wuint32(buffer.length, 'big', request, offset);
  offset += 4;
  buffer.copy(request, offset);

  return offset + buffer.length;
}


function _readHeader(response, expect) {
  // assert.ok(response);

  var len = ctype.ruint32(response, 'big', 0);
  var type = ctype.ruint8(response, 'big', 4);

  return (expect === type ? len : -1);
}


function _writeHeader(request, tag) {
  ctype.wuint32(request.length - 4, 'big', request, 0);
  ctype.wuint8(tag, 'big', request, 4);
  return 5;
}



module.exports = function createServer(opt, events) {

  function routeEvent(stream) {
    //console.log('client connected');

    stream.on('end', function() {
      // console.log('client disconnected');
    });

    stream.on('error', function(err) {
      console.log(err);
      // stream.write({ error: err.toString() });
    });

    var write = stream.write;

    // stream.write = function() {
    //   var args = arguments;
    //   if (typeof args[0] == 'object') {
    //     args[0] = JSON.stringify(args[0]) + '\n';
    //   }
    //   write.apply(stream, args);
    // };

    // stream.write(BANNER);
    //  https://tools.ietf.org/id/draft-miller-ssh-agent-01.html#messagenum
    stream
      // .pipe(split())
      // .pipe(parse())
      .on('data', function(response) {
        console.log(response.toString("hex"))

        var len = ctype.ruint32(response, 'big', 0);
        var type = ctype.ruint8(response, 'big', 4);

        switch (type) {
          // case 13:
          //   /*
            
          //   */
          //   console.log("SIGNREQUEST")
          //   console.log(response)
          //   break;
          case 11:

            var kbt = Buffer.from(getCharCodes("ssh-ed25519"));
            var _key = Buffer.from("439083de2ae68fd822a5b172d299403feecb96f25e299a8129ffde012aa649e2", "hex");

            var key = Buffer.alloc(4 + kbt.length + 4 + _key.length);
            var offset;
            offset = 0;

            ctype.wuint32(kbt.length, 'big', key, offset);
            offset += 4;
            kbt.copy(key, offset);
            offset = offset + kbt.length;

            // offset = _writeString(key, kbt, offset);
            // _writeString(key, _key, offset);
            // offset += 4;
            
            ctype.wuint32(_key.length, 'big', key, offset);
            offset += 4;
            _key.copy(key, offset);
            offset = offset + kbt.length;

            var kb_c = Buffer.from("ok");
            var request = Buffer.alloc(4 + 1 + 4 + 1 + 4 + key.length + 4 + kb_c.length + 4);
            // var request = new Buffer(4 + 1 + 4 + key._raw.length + 4 + data.length + 4);
            // var offset = _writeHeader(request, PROTOCOL.SSH2_AGENTC_SIGN_REQUEST);
            // offset = _writeString(request, key._raw, offset);
            // offset = _writeString(request, data, offset);
            // ctype.wuint32(0, 'big', request, offset);
            // return request;

            offset = _writeHeader(request, PROTOCOL.SSH_AGENT_IDENTITIES_ANSWER);
            ctype.wuint32(1, 'big', request, offset);
            offset += 4;
            offset = _writeString(request, key, offset);
            offset = _writeString(request, kb_c, offset);
            ctype.wuint32(0, 'big', request, offset);

            stream.write(request);
            break;
          case 13:
          default:
            
            
            response = response.slice(5);
            console.log(len, type, response)

            if (response.length) {
              var blobkey = _readString(response, 0);
              var indata = _readString(response, blobkey.len+4);
              // var signature = _readString(blob, type.length + 4);

              console.log({
                blob:blobkey.str.toString("base64"),
                indata: indata.str,  // <-- sign this
                // signature: signature.toString('base64'),
                // _raw: signature
              });
            }
            break;
        }

        // for(var i in events) {
        //   if (events[i].test(stream, data)) {
        //     events[i].handler(stream, data);
        //   }
        // }
      });

  }

  var server = net.createServer(routeEvent);

  return server;

};

function getCharCodes(s) {
  let charCodeArr = [];

  for (let i = 0; i < s.length; i++) {
    let code = s.charCodeAt(i);
    charCodeArr.push(code);
  }

  return charCodeArr;
}

function _readString(buffer, offset) {
  // assert.ok(buffer);
  // assert.ok(offset !== undefined);

  var len = ctype.ruint32(buffer, 'big', offset);
  offset += 4;

  var str = Buffer.alloc(len);
  buffer.copy(str, 0, offset, offset + len);

  return {str:str,len:len};
}