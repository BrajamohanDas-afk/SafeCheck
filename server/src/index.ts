import express, {Request, Response} from 'express';
import cors from 'cors'; // This is for the communication of frontend and backend
import dotenv from 'dotenv'; //This is for the env for using virustotal
import multer from 'multer'; //This is for the file upload
import fetch from 'node-fetch';
import FormData from 'form-data'; //This is useful for sending files and other data to the APIs or server

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;

if(!VT_API_KEY){
    console.error({error : 'VIRUSTOTAL_API_KEY is not set in the env'});
    process.exit(1);
}

//MIDDLEWARE

app.use(cors()); //Allow frontend to call this server
app.use(express.json());

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {fileSize: 32 * 1024 * 1024} //32MB MAX
});

//ROUT 1: HEALTH CHECK

app.get('/health', (req:Request, res:Response)=>{
    res.json({
        status: "The server is running",
        timeStamp: new Date().toISOString(),
        vtKeyLoaded: !!VT_API_KEY
    });
});

//ROUT 2: CHECK IF THE FILR HASH EXISTS IN THE VIRUSTOTAL

app.get('/api/check-hash',async (req:Request, res:Response)=>{
    const { hash } = req.query;

    if(!hash || typeof hash !== 'string'){
        return res.status(400).json({error: 'Missing or invalid hash parameter'});
    }

    console.log(`Checking Hash: ${hash.substring(0,16)}...`);

    try{ 
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`,{
            method: 'GET',
            headers: { 'x-apikey': VT_API_KEY },
        })

        if(response.status===404){
            console.log(`HASH not found in the VT database`);
            return res.status(404).json({error: 'File not found in VIRUSTOTAL database'});
        }

        const data = await response.json();

        if(!response.ok){
            console.error(`VT API error:`, data);
            return res.status(response.status).json(data);
        }

        console.log(`Hash found on VT database (cached result)`);
        return res.status(200).json(data);
    } catch (error){
        console.error(`VIRUSTOTAL hash lookup error`, error);
        return res.status(500).json({error: 'Failed to check hash'});
    }
});

//ROUT 3:Upload a file for VIRUSTOTAL for scanning

app.post('/api/scan', upload.single('file'), async(req:Request, res:Response)=>{
    if(!req.file){
        return res.status(400).json({error:"No file uploaded"});
    }

    console.log(`Uploading file: ${req.file.originalname} (${req.file.size} Bytes)`);

    try{
        const formData = new FormData();
        formData.append('file', req.file.buffer, {
            filename: req.file.originalname,
            contentType: req.file.mimetype,  //This tells the type of the file 
        } as any );

        
        const response = await fetch('https://www.virustotal.com/api/v3/files',{
            method: 'POST',
            headers: {
                'x-apikey': VT_API_KEY,
                ...formData.getHeaders(), //Critical: Add a correct type of multipart boundary
            },
            body: formData,
        });

        const data = await response.json();

        if(!response.ok){
            console.error(`VT API error:`, data);
            return res.status(response.status).json(data);
        }
        
        const analysisId = (data as any)?.data?.id || 'unknown';
        console.log(`File uploaded successfully. Analysis ID: ${analysisId}`);
        return res.status(200).json(data);
    } catch(error){
        console.error(`VirusTotal file scan error:`, error);
        return res.status(500).json({ error: 'Failed to scan file' });
    }
});

//START THE SERVER

app.listen(PORT, () => {
  console.log(`\nServer running on http://localhost:${PORT}`);
  console.log(`VirusTotal API key loaded: ${VT_API_KEY.substring(0, 8)}...`);
  console.log(`Ready to accept requests from frontend\n`);
});