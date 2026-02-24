import multer from 'multer';
import path from 'path';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';
import { AppError } from '../core/errors/AppError';

/**
 * We switch to Disk Storage to prevent OOM (Out of Memory) issues.
 * Files are temporarily stored in the system's temp directory and 
 * processed from there rather than sitting in Node.js RAM.
 */
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, os.tmpdir());
    },
    filename: (req, file, cb) => {
        cb(null, uuidv4());
    }
});

const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    const allowedMimes = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/csv'
    ];

    if (allowedMimes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new AppError(`File type ${file.mimetype} is not supported`, 400, 'UNSUPPORTED_FILE_TYPE'));
    }
};

export const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 1 // Only one file at a time for financial entries
    }
});