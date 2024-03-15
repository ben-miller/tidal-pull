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
const scopes = ['collection.read', 'playlists.read'];
const clientId = process.env.TIDAL_CLIENT_ID;
const clientSecret = process.env.TIDAL_CLIENT_SECRET;

await auth.init({
    clientId,
    clientSecret,
    credentialsStorageKey: 'key',
    clientUniqueKey: 'foo',
    scopes: scopes,
    tidalAuthServiceBaseUri: undefined,
    tidalLoginServiceBaseUri: undefined,
});

const loginUrl = await auth.initializeLogin({
    loginConfig: {},
    redirectUri,
});

app.get('/oauth2/callback', async (req: Request, res: Response) => {
    const { code, code_verifier } = req.query;
    console.log('code:', code);
    console.log('query:', req.query);

    if (typeof code !== 'string') {
        res.status(400).send('Invalid request');
        return;
    }

    const tokenResponse = await axios.post('https://auth.tidal.com/v1/oauth2/token', 
        qs.stringify({
            grant_type: 'authorization_code',
            client_id: process.env.TIDAL_CLIENT_ID,
            code: code,
            redirect_uri: 'http://localhost:8080/oauth2/callback2',
            client_secret: process.env.TIDAL_CLIENT_SECRET,
        }), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        }
    );

    const accessToken = tokenResponse.data.access_token;
    // Use the access token as needed

    // Redirect or respond after successful token acquisition
    res.redirect('/success-page');

    process.exit(0);
});

//app.get('/oauth2/callback2', async (req: Request, res: Response) => {
//    console.log('callback2');
//});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

await open(loginUrl);

