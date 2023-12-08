# *What* is OAuth?

- **authorization framework**-> <mark style="background: #FF5582A6;">enables websites and web applications to request limited access to a user's account on another application</mark>.
- the user fine-tunes the shared data. 

# *How* does OAuth 2.0 work?

- **Client application** - The website or web application that *wants to access* the user's data.
- **Resource owner** - *The user* whose data the client application wants to access.
- **OAuth service provider** - The website or application that *controls the user's data* and access to it. -> through API 

1. The <mark style="background: #BBFABBA6;">client requests access</mark> to a subset of the user's data, specifying which grant type they want to use and what kind of access they want.
2. The <mark style="background: #BBFABBA6;">user is prompted to log in</mark> to the OAuth service and explicitly give their consent for the requested access.
3. The <mark style="background: #BBFABBA6;">client application receives a unique access token</mark> that proves they have permission from the user to access the requested data.  (depending on the grant type.)
4. The client application uses this access token to make <mark style="background: #BBFABBA6;">API calls fetching the relevant data</mark> from the resource server.
# OAuth grant types

/git