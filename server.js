import express from 'express';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';

const app = express();
app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 10000;
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const ADMIN_IDS = new Set((process.env.ADMIN_IDS || '').split(',').map(x=>x.trim()).filter(Boolean));
const db = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY) : null;

function validateInitData(initData) {
  if (!BOT_TOKEN || !initData) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');
  const dataCheck = [...params.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>`${k}=${v}`).join('\\n');
  const secret = crypto.createHmac('sha256','WebAppData').update(BOT_TOKEN).digest();
  const calculated = crypto.createHmac('sha256',secret).update(dataCheck).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(calculated), Buffer.from(hash))) return null;
  const authDate = Number(params.get('auth_date') || 0);
  if (!authDate || Math.floor(Date.now()/1000)-authDate > 86400) return null;
  try { return JSON.parse(params.get('user') || '{}'); } catch { return null; }
}

function auth(req,res,next){
  const user = validateInitData(req.headers['x-telegram-init-data'] || '');
  if (!user?.id) return res.status(401).json({error:'Telegram authentication required'});
  req.tgUser = user;
  next();
}
function admin(req,res,next){ if(!ADMIN_IDS.has(String(req.tgUser.id))) return res.status(403).json({error:'Admin only'}); next(); }

app.get('/api/health',(req,res)=>res.json({ok:true, database:!!db}));

app.get('/api/me',auth,async(req,res)=>{
  if(!db) return res.json({user:req.tgUser,points:0,rank:null});
  const {data,error}=await db.from('users').select('*').eq('telegram_id',req.tgUser.id).maybeSingle();
  if(error) return res.status(500).json({error:error.message});
  if(!data){
    const {data:created,error:e}=await db.from('users').insert({telegram_id:req.tgUser.id,username:req.tgUser.username||null,first_name:req.tgUser.first_name||''}).select().single();
    if(e) return res.status(500).json({error:e.message});
    return res.json({user:created,points:0,rank:null});
  }
  const {count}=await db.from('users').select('*',{count:'exact',head:true}).gt('points',data.points);
  res.json({user:data,points:data.points,rank:(count??0)+1});
});

app.get('/api/matches',auth,async(req,res)=>{
  if(!db) return res.json({matches:[]});
  const {data,error}=await db.from('matches').select('*').order('kickoff_at',{ascending:true});
  if(error) return res.status(500).json({error:error.message});
  res.json({matches:data||[]});
});

app.get('/api/leaderboard',auth,async(req,res)=>{
  if(!db) return res.json({users:[]});
  const {data,error}=await db.from('users').select('telegram_id,username,first_name,points').order('points',{ascending:false}).limit(100);
  if(error) return res.status(500).json({error:error.message});
  res.json({users:data||[]});
});

app.get('/api/my-predictions',auth,async(req,res)=>{
  if(!db) return res.json({predictions:[]});
  const {data,error}=await db.from('predictions').select('id,match_id,home_score,away_score,points,created_at,matches(home_team,away_team,kickoff_at,status)').eq('telegram_id',req.tgUser.id).order('created_at',{ascending:false});
  if(error) return res.status(500).json({error:error.message});
  res.json({predictions:data||[]});
});

app.post('/api/predictions',auth,async(req,res)=>{
  if(!db) return res.status(503).json({error:'Database is not configured yet'});
  const matchId=String(req.body.match_id||''); const h=Number(req.body.home_score); const a=Number(req.body.away_score);
  if(!matchId||!Number.isInteger(h)||!Number.isInteger(a)||h<0||a<0||h>20||a>20) return res.status(400).json({error:'Invalid score'});
  const {data:match,error:me}=await db.from('matches').select('*').eq('id',matchId).single();
  if(me||!match) return res.status(404).json({error:'Match not found'});
  if(match.status!=='open' || new Date(match.kickoff_at).getTime()<=Date.now()) return res.status(409).json({error:'Predictions are closed'});
  const {data,error}=await db.from('predictions').upsert({match_id:matchId,telegram_id:req.tgUser.id,home_score:h,away_score:a},{onConflict:'match_id,telegram_id'}).select().single();
  if(error) return res.status(500).json({error:error.message});
  res.json({ok:true,prediction:data});
});

app.post('/api/admin/matches',auth,admin,async(req,res)=>{
  if(!db) return res.status(503).json({error:'Database is not configured yet'});
  const {home_team,away_team,kickoff_at}=req.body;
  if(!home_team||!away_team||!kickoff_at) return res.status(400).json({error:'Missing fields'});
  const {data,error}=await db.from('matches').insert({home_team,away_team,kickoff_at,status:'open'}).select().single();
  if(error) return res.status(500).json({error:error.message});
  res.json({match:data});
});

app.post('/api/admin/results',auth,admin,async(req,res)=>{
  if(!db) return res.status(503).json({error:'Database is not configured yet'});
  const matchId=String(req.body.match_id||''); const h=Number(req.body.home_score); const a=Number(req.body.away_score);
  if(!matchId||!Number.isInteger(h)||!Number.isInteger(a)||h<0||a<0) return res.status(400).json({error:'Invalid result'});
  const {data:match,error:me}=await db.from('matches').select('*').eq('id',matchId).single();
  if(me||!match) return res.status(404).json({error:'Match not found'});
  const {data:preds,error:pe}=await db.from('predictions').select('*').eq('match_id',matchId);
  if(pe) return res.status(500).json({error:pe.message});
  for(const p of preds||[]){
    let points=1;
    if(p.home_score===h && p.away_score===a) points=10;
    else if(Math.sign(p.home_score-p.away_score)===Math.sign(h-a)) points=5;
    else if((p.home_score===p.away_score)===(h===a)) points=3;
    await db.from('predictions').update({points}).eq('id',p.id);
    const {data:u}=await db.from('users').select('points').eq('telegram_id',p.telegram_id).single();
    if(u) await db.from('users').update({points:(u.points||0)+points}).eq('telegram_id',p.telegram_id);
  }
  const {error}=await db.from('matches').update({home_score:h,away_score:a,status:'finished'}).eq('id',matchId);
  if(error) return res.status(500).json({error:error.message});
  res.json({ok:true});
});

app.listen(PORT,'0.0.0.0',()=>console.log(`FM100 running on ${PORT}`));
