import express from 'express';
import defendjs from './core/security/middleware.js';
import cors from 'cors';

const app = express();


app.use(express.json());
app.use(cors());
//add the middleware library
app.use(defendjs);

app.get('/', (req, res) =>{
    res.send(
        'Defend Js to the Rescue'
    );
}
)

app.post('/api/data', (req, res) => {
    // Handle the post request
    res.send('Data received');
});


app.listen(3001, ()=>{
    console.log('server is running on 3001');
})