#ifndef STORAGE_H_
#define STORAGE_H_

// Pointer for Block 1 ---------------

#define RES_PSK_ISNEW          1
#define LEN_PSK_ISNEW          1

#define RES_NEWPSK             2
#define LEN_NEWPSK            16

#define SESSION_LIST_LEN      10
#define RES_SESSION_LIST      18
#define LEN_SESSION_LIST     640

// Pointer for Block 2 ---------------

#define RES_KEY_BLOCK_LIST (4096 + 1)
#define LEN_KEY_BLOCK_LIST   800

//------------------------------------

#endif /* STORAGE_H_ */
