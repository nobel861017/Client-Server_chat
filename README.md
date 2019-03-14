# Computer Network Final Project
---
- b05902121 黃冠博
- b04902131 黃郁凱
---
## Protocol Specification
- These are the flags for operators
    - ```line_protocol_magic``` specifies whether the header is a request or a response
    - ```line_protocol_op``` specifies the operator which implies what the request wants to do
    - ```line_protocol_status``` specifies the status of the sender of the response
```
typedef enum {
    LINE_PROTOCOL_MAGIC_REQ = 0x90,
    LINE_PROTOCOL_MAGIC_RES = 0x91,
} line_protocol_magic;

typedef enum {
    LINE_PROTOCOL_OP_LOGIN = 0x00,
    LINE_PROTOCOL_OP_SYNC_META = 0x01,
    LINE_PROTOCOL_OP_SYNC_LOG = 0x02,
    LINE_PROTOCOL_OP_REGISTER = 0x03,
    LINE_PROTOCOL_OP_END = 0x04,
    LINE_PROTOCOL_OP_MATCH = 0x05,
    LINE_PROTOCOL_OP_UNMATCH = 0x06,
    LINE_PROTOCOL_OP_ADD_FRIEND = 0x07,
} line_protocol_op;

typedef enum {
    LINE_PROTOCOL_STATUS_OK = 0x00,
    LINE_PROTOCOL_STATUS_FAIL = 0x01,
    LINE_PROTOCOL_STATUS_MORE = 0x02,
} line_protocol_status;
```

- This is the structure for the header

```
typedef union {
    struct {
        uint8_t magic;
        uint8_t op;
        uint8_t status;
        uint16_t client_id;
        uint32_t datalen;
    } req;
    struct {
        uint8_t magic;
        uint8_t op;
        uint8_t status;
        uint16_t client_id;
        uint32_t datalen;
    } res;
    uint8_t bytes[9];
} line_protocol_header;
```

- This is the structure for login
    - It records the user name, password and the md5 hash of the password
```
typedef union {
    struct {
        line_protocol_header header;
        struct {
            uint8_t user[USER_LEN_MAX];
            char passwd[PASSWD_LEN_MAX];
            uint8_t passwd_hash[MD5_DIGEST_LENGTH];
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) + MD5_DIGEST_LENGTH * 2];
} line_protocol_login;
```

- This is the structure for match request
    - It records the username that the sender of the request wants to match

```
typedef union {
    struct {
        line_protocol_header header;
        struct {
            char match_username[USER_LEN_MAX];
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) + sizeof(char) * USER_LEN_MAX];
} line_protocol_match;
```

- This is the structure for message files
    - it is for sending messages and files
    - ``is_msg`` specifies whether it header is for message sending or not
    - ``first`` specifies whether this is the first fragment of the file
    - ``finish`` specifies whether this is the last fragment of the file
    - ``data_len`` specifies the length of the message or file(fragment size, not the whole size of the file)
    - ``filename`` specifies the name of the sending file
    - ``sender`` specifies the name of the sender
    - ``recv_user`` specifies the name of the reciever
```
typedef union {
    struct {
        line_protocol_header header;
        struct {
            int is_msg;
            int first;
            int finished;
            int data_len;
            char data[DATA_LEN_MAX];
            char sender[FILE_LEN_MAX];
            char filename[FILE_LEN_MAX];
            char recv_user[USER_LEN_MAX];
        } body;
    } message;
    uint8_t bytes[sizeof(line_protocol_header) +
                    sizeof(int) * 4 +
                    sizeof(char) * (DATA_LEN_MAX + FILE_LEN_MAX*2 + USER_LEN_MAX)];
} line_protocol_msg_file
```

## User and Operator Guide
### Instructions on how to run server & clients
- In ```src```:
	- make
	- make clean

- In ```bin``` (need three terminals):
	- ./port_register
	- ./server ../config/server.cfg
	- ./client ../config/client.cfg
### User Interface(terminal) Guide 
- Once you run client
    - Login: 0, Signup: 1
    - It will ask you to enter user name and password
- Once login success
    - ```Chat: c / Quit: q```
    - If quit:
        - logout from server
        - Close chating window
    - If chat:
        - Insert name who you want to chat with 
        - Please enter what you want to say
        - command ":q" go back to ```Chat: c / Quit: q``` stage
        - command ":f" send file to current matching client
            - enter [num of files] [file1] [file2] ...
        - command ":a" add friend with current matching client
            - add friend to friend file list
        - command ":l" list out the historical sent and received messages of the current matching client

## System and Program Design
### Message Sending
- message format:
    - ```is_msg``` specifies whether this message is a chatting message or a file-sending message

    ex : 1,0,1546498631,hi

    |is_msg|is_read|time|message content|
    | :--------: | :--------: | :--------: | :--------: |
    | 1| 0    |1546498631    | hi    |

- When user A sends a chatting message "hi" to user B, the message is written to a file ```sdir/A/talk_B.csv``` in the format above
- When user B is online, the server automatically sends the messages with ```is_read == 0 ``` to user B, and sets the flag ```is_read``` to 1.
- Only the messages with ```is_msg == 1``` are printed to ```stdout```.
- If ```is_msg == 0```, this message is a file-sending message, the output of the receiver is:
    - ```Client B receive file as follow: ../cdir/[receiver name]/file1.txt```
- The file ```sdir/A/talk_B.csv``` and ```sdir/B/talk_A.csv``` is the log kept on the server for user A to query.
    - When user A types command ":l", the server reads the two files ```sdir/A/talk_B.csv``` and ```sdir/B/talk_A.csv```, reorders the messages according to the time and forwards the reordered messages to user A.
### Sending File
- Read the file with ``read()`` with buffer size 40960 bytes
- Send the data to server, and the server will forward it to the current matched user.
- The sending record we be saved at ```sdir/A/talk_B.csv``` in the format below, where A is the sender and B is the receiver.

    |is_msg|is_read|time|message content|
    | :--------: | :--------: | :--------: | :--------: |
    | 0| 0    |1546500884    | file1.txt    |

- The client that receives the file actually receives fragments of the file.
    - When ```first == 1```, the client opens or creates the file with the specified file name and appends the received data to the file.
    - When ```finished == 1```, this means that the receiver has received the last fragment of the file, and will write it to the corresponding file and closes the file after finish writing.
        - Notice that we do not need to reopen the file when we receive a new file fragment, since continuously openning and closing files wastes lots of time.
- In order to send multiple files at once, we use multi-thread to send every file(One thread for each file).

## Bonus
- Password ```md5 hash```.
    - server checks the ```md5``` of the correct password with the ```md5``` of the password the user enters
        - If they are the same: login success
        - Else: login fail
- Add friends
    - Already matched users can type the command ":a" to add the currently matched friend to its friend list. By the way, the currently matched friend also adds the user that sent the add-friend request to its friend list.
- Logout
    - Server records the client to be offline
    - During ```Chat: c / Quit: q``` stage, the user can logout by typing the command "q". The server then erases the clients ``conn_fd`` from the table.
    - The client proccess terminates.
- Message Sending Encryption
    - Caesar Cypher Algorithm Encryption
    - The chatting messages are encrypted before sending to the server. Hence, the server can not see the original text.
- Send stickers
    - One can send stickers to the other by typing ``:s [sticker number]``
    - There are 5 stickers numbered with 1 to 5. Users can add tailor made stickers for themselves.
- Message send time
    - When client receives a message, the send time of the message is shown aside.
    - ex: (5 seconds ago)
- Can send file and chat with other users simultaneously.
