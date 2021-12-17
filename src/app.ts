import speakeasy from 'speakeasy'
import express   from 'express'
import qrcode    from 'qrcode'


const secretKey: string =  'OM4EU4DLNUVGCTROG4QUST3MM52SCRLPGJYHCPRQN45UCYJOKAQQ';  // TODO: store this in an env variable

const app: express.Application = express();

app.use(express.static('./public/'));            // static assets
app.use(express.urlencoded({ extended: true })); // parse data
app.use(express.json());                         // parse json

app.get('/', (req: express.Request, res: express.Response) => res.status(200).sendFile('index.html'));

app.get('/totp/generate', (req: express.Request, res: express.Response) =>
{
	const secret: speakeasy.GeneratedSecret = speakeasy.generateSecret( { name: "Skeeob" });
	qrcode.toDataURL(secret.otpauth_url!, (err, data) => 
	{
		if (err)
			return res.status(500).send(err);
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
		return res.status(401).json({ success: false, message: 'Please provide a token'});

	const verified: boolean = speakeasy.totp.verify({
		secret: secretKey,
		encoding: 'base32',
		token: token
	});

	if (!verified)
		return res.status(401).json({ success: false, message: 'Unauthorized'});
	
	return res.status(200).json({ success: true, message: 'Token verified'});
});

app.listen(5000, () => console.log('Listening on: 5000...'));