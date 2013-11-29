Spec
====

The fs looks like this

    /public
    /private
    /contacts
    /chans/#9me
           #socialfs
    /circles/work
             familly
  	   friends

The fs maintains his own list of know users (go9p supports that)
Authentification is done with rsa keys.
The rights on the files and folders are different depending if you are mounting your own socialfs or the socialfs of one of your contacts.

 * _public_ is of type Chat, everybody should have read and write permissions on it. If you want to speak publicly to someone, mount his socialfs and write to his public. See this as a "all" in facebook
 * _private_ is of type Chat also, you can only write to it. Except if you mount your own socialfs, in this special case you can read incoming private messages from your contacts
 * _contact_ When read, contact prints the list of your contacts, this means their nick in your file system plus their public key plus the circles they belongs to. When written, it can be used to add a new contact to your own socialfs, or to suggest a new contact to a socialfs whom the owner has given write permissions to others
 * _chans/_ Contains files of type Chat, use touch to create a chan, read and write have the same behaviour as _public_
 * _circles/_ is used to manage circles of contacts. Use touch to create a new circle. Writing to a circle could be redirected to each _private_ of your contacts belonging to this circle. But I don't know if it is a good idea yet. Also, reading a circle could return a merge of all your contact's _public_ (only their own messages though)

