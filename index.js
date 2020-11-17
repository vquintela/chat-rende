const express = require('express');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const rsaWrapper = require('./components/rsa-wrapper');
const aesWrapper = require('./components/aes-wrapper');

rsaWrapper.initLoadServerKeys(__dirname);
rsaWrapper.serverExampleEncrypt();

app.use(express.static(__dirname + '/static'));

// GENERANDO AES KEY
const aesKey = aesWrapper.generateKey();
let encryptedAesKey = rsaWrapper.encrypt(rsaWrapper.clientPub, (aesKey.toString('base64')));

// web socket connection event
io.on('connection', function(socket){
    console.log('nueva conecion', socket.id);
    
    // Recibiendo mensajes en RSA
    socket.on('rsa client encrypted message', function (data) {
        console.log('Mensaje del cliente en RSA');
        console.log('Mensaje encriptado', '\n', data);
        console.log('Mensaje desencriptado', '\n', rsaWrapper.decrypt(rsaWrapper.serverPrivate, data));
        // Enviando mensaje con RSA
        let encrypted = rsaWrapper.encrypt(rsaWrapper.clientPub, rsaWrapper.decrypt(rsaWrapper.serverPrivate, data));
        io.sockets.emit('rsa server encrypted message', encrypted);
    });

    // Enviando llave AES
    console.log('Clave aes al cliente', '\n', encryptedAesKey)
    socket.emit('send key from server to client', encryptedAesKey);
    
    // Recibiendo mensaje en AES desde el cliente
    socket.on('aes client encrypted message', function (data) {
        console.log('El servidor recibio un mensaje en AES desde el cliente', '\n', 'El mensaje encriptado es', '\n', data);
        console.log('Mensaje desencriptado', '\n', aesWrapper.decrypt(aesKey, data));       
        // Enviando mensaje al cliente
        let message = aesWrapper.createAesMessage(aesKey, aesWrapper.decrypt(aesKey, data));
        io.sockets.emit('aes server encrypted message', message);
    });
});

http.listen(3000, function(){
    console.log('listening on *:3000');
});
