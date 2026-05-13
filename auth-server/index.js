import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { randomBytes, createHash } from 'crypto';
import { SignJWT, exportJWK, importPKCS8 } from 'jose';

const app = express();
app.use(bodyParser.urlencoded({extended : false}));
app.use(bodyParser.json());
app.use(cookieParser());

const clients = new Map();
const authorizationCodes = new Map();
const refreshTokens = new Map();