$(document).ready(function(){
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/chat');

    socket.on('new_message', function(msg) {
        chat_string = '';

        for (var i = 0; i < msg.length; i++){
            var message = "Received message from " + msg[i].user + " (" + msg[i].posted + "): " + msg[i].message;
            chat_string = chat_string + '<p>' + message + '</p>';
        }

        $('#log').html(chat_string);
    });

});