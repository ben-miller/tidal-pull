import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import axios from 'axios';
import qs from 'qs';
import open from 'open';
import * as auth from './tidal-auth.js';

console.log('Hello, world!')

dotenv.config();
const app = express();
const PORT = process.env.PORT || 8080;
const redirectUri = 'http://localhost:8080/oauth2/callback';
const scopes = ['collection.read', 'playlists.read', 'collection.write', 'playlists.write'];
const clientId = process.env.TIDAL_CLIENT_ID;
const clientSecret = process.env.TIDAL_CLIENT_SECRET;

// TODO User requests resource
// App checks if user is authorized. If so, request resource. If not,
// start authorization flow.

// Init and store credentials in local storage
console.log('Step 0: Init auth, store credentials in local storage');
await auth.init({
    clientId,
    clientSecret,
    credentialsStorageKey: 'key',
    clientUniqueKey: 'foo',
    scopes: scopes,
    tidalAuthServiceBaseUri: undefined,
    tidalLoginServiceBaseUri: undefined,
});

// Build the authorization URL, code challenge, and code verifier
const { authorizeUrl, codeChallenge } = await auth.initializeLogin({
    loginConfig: {},
    redirectUri,
});

console.log('authorizeUrl:', authorizeUrl);
console.log('codeChallenge:', codeChallenge);

app.get('/oauth2/callback', async (req: Request, res: Response) => {
    // Step 6: If authorize request (step 5) is successul, it will redirect
    // to this endpoint along with an auth code and code verifier (hashed auth code).
    const { code, code_verifier } = req.query;
    console.log('code:', code);
    console.log('query:', req.query);

    if (typeof code !== 'string') {
        res.status(400).send('Invalid request');
        return;
    }

    // Step 7: App presents auth code to Tidal's token endpoint to get an access token.
    console.log('Step 7: Request access token');
    await auth.finalizeLogin("?code=" + code + "&code_verifier=" + code_verifier);

    // Get credentials
    const credentials = await auth.credentialsProvider.getCredentials();
    console.log(credentials);

    //const accessToken = tokenResponse.data.access_token;
    // Use the access token as needed
    
    // Sleep for a bit
    await new Promise(resolve => setTimeout(resolve, Math.random() * (4000 - 2000) + 2000));

    // Redirect or respond after successful token acquisition
    // Step 8: Tidal service issues an access token.
    console.log('Step 8: Request resource using access token:', credentials.token);
    await axios.get('https://listen.tidal.com/v2/my-collection', {
        headers: {
            Accept: 'application/json',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.5',
            authorization: `Bearer ${credentials.token}`,
            Host: 'listen.tidal.com',
            Origin: 'http://listen.tidal.com',
            Referer: 'http://listen.tidal.com/'
        }
    }).then((response) => {
        console.log('Response:', response.data);
        res.send('Success');
    }).catch((err) => {
        console.error('Error:', err);
        res.status(500).send('Error');
    });

    process.exit(0);
});

// Callback for the second redirect
app.get('/oauth2/callback2', async (req: Request, res: Response) => {
    console.log('query:', req.query);
    res.send('Success');
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

// Step 1 (implied): App asks user whether to link to Tidal
// Step 2: If yes, hit https://login.tidal.com/authorize
await open(authorizeUrl); 
// Step 3: Returns authorization page to app.
// Step 4: App displays the authorization page to user.
// Step 5: User authorizes app to access Tidal.

