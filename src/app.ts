import express from 'express';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import * as uuid from 'uuid';

import { JsonDB } from 'node-json-db';
import { Config } from 'node-json-db/dist/lib/JsonDBConfig';

import dotenv from 'dotenv';
dotenv.config();

// user credentials
const SECRET_KEY: string = process.env.SECRET_KEY!;
const USERNAME:  string = process.env.USERNAME!;

const jsondb = new JsonDB(new Config('db_twoFA', true, true, '/'));
const app: express.Application = express();

app.use(express.static('./src/public/')); // static assets
app.use(express.urlencoded({ extended: true })); // parse data
app.use(express.json()); // parse json

app.get('/', (req: express.Request, res: express.Response) => res.status(200).sendFile('index.html'));

app.get('/totp/generate', (req: express.Request, res: express.Response) =>
{
	const secret: speakeasy.GeneratedSecret = speakeasy.generateSecret({ name: USERNAME });
	qrcode.toDataURL(secret.otpauth_url!, (err: Error, data: string) => 
	{
		if (err)
		{
			console.log(err);
			return res.status(500).send('Unable to generate QR code!');
		}
		else
		{
			const qrcodeData: string = "<img src=\"" + data + "\">\n" +
				"<code>" +
				"\n<br>Secret key (base32): " + secret.base32 +
				//"\n<br>hex: " + secret.hex +
				"\n</code>";
			return res.status(200).send(qrcodeData);
		}
	});
});

app.post('/totp/validate', (req: express.Request, res: express.Response) =>
{
	const { token } = req.body;
	if (!token)
		return res.status(401).json({ success: false, message: 'Please provide a token' });

	const verified: boolean = speakeasy.totp.verify({
		secret: SECRET_KEY,
		encoding: 'base32',
		token: token
	});

	if (!verified)
		return res.status(401).json({ success: false, message: 'Unauthorized' });

	return res.status(200).json({ success: true, message: 'Token verified' });
});

// Register user and generate secret key
app.post('/register', (req: express.Request, res: express.Response) =>
{
	const { username } = req.body; // TODO: check db for uniqueness 
	const tempSecret = speakeasy.generateSecret({ name: username });

	const userID = uuid.v4();
	const path = `/user/${userID}`;

	jsondb.push(path, { userID: userID, username: username, tempSecret: tempSecret });
	return res.status(200).json({ userID: userID, username: username, tempSecret: tempSecret });
});

// Verify the user and make the secret permanent
app.post('/verify', (req: express.Request, res: express.Response) =>
{
	const { userID, token } = req.body;
	try 
	{
		const path = `/user/${userID}`;
		const user = jsondb.getData(path);
		const { base32: secret } = user.tempSecret; // rename tempSecret to secret

		const verified = speakeasy.totp.verify({
			secret: secret,
			encoding: 'base32',
			token: token
		});

		if (verified)
		{
			jsondb.push(path, { userID: userID, username: user.username, secret: user.tempSecret });
			return res.status(200).json({ verified: true });
		}
		return res.status(200).json({ verified: false });
	}
	catch(err)
	{
		console.log(err);
		return res.status(500).json({ success: false, message: 'Unable to verify user!' });
	}
});

// Validate the user (TOTP token validation)
app.post('/validate', (req: express.Request, res: express.Response) =>
{
	const { userID, token } = req.body;
	try 
	{
		const path = `/user/${userID}`;
		const user = jsondb.getData(path);

		const validated = speakeasy.totp.verify({
			secret: user.secret.base32,
			encoding: 'base32',
			token: token
		});

		if (validated)
			return res.status(200).json({ validated: true });

		return res.status(200).json({ validated: false });
	}
	catch(err)
	{
		console.log(err);
		return res.status(500).json({ success: false, message: 'Unable to validate user!' });
	}
});

app.listen(5000, () => console.log('Listening on http://localhost:5000'));