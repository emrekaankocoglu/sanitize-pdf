#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import crypto from 'crypto';
import { Buffer } from 'buffer';
import util from 'util';
import zlib from 'zlib';

const require = createRequire(import.meta.url);
const pdfjsLib = require('pdfjs-dist');
const nodeCanvas = require('canvas');
const { Canvas, Image } = nodeCanvas;

// Mock browser context for PDF.js
global.navigator = {
  userAgent: 'node',
};

// Parse command line arguments
const args = process.argv.slice(2);
let pdfPath = '';
let outputDir = './pdf_extracted';
let password = '';

if (args.length > 0) {
  if (args[0] === '-f' || args[0] === '--file') {
    pdfPath = args[1];
    
    for (let i = 2; i < args.length; i++) {
      if (args[i] === '-o' || args[i] === '--output') {
        outputDir = args[i + 1];
        i++;
      } else if (args[i] === '-p' || args[i] === '--password') {
        password = args[i + 1];
        i++;
      }
    }
  } else {
    pdfPath = args[0];
    
    for (let i = 1; i < args.length; i++) {
      if (args[i] === '-o' || args[i] === '--output') {
        outputDir = args[i + 1];
        i++;
      } else if (args[i] === '-p' || args[i] === '--password') {
        password = args[i + 1];
        i++;
      }
    }
  }
}

// Create hash for filename generation
function createHash(data) {
  return crypto.createHash('md5').update(data).digest('hex').substring(0, 8);
}

// Utility encryption/decryption functions
const ENCRYPTION_METHODS = {
  NONE: 'None',
  PASSWORD: 'Password Protected',
  RC4: 'RC4',
  AES: 'AES',
  IDENTITY: 'Identity',
  CUSTOM: 'Custom',
  UNKNOWN: 'Unknown'
};

// Helper function to decode escaped or encoded text
function decodeText(text) {
  try {
    // Try to decode if it looks like a hex or base64 string
    if (/^[0-9A-F]+$/i.test(text) && text.length % 2 === 0) {
      // Decode as hex
      const decoded = Buffer.from(text, 'hex').toString();
      return { originalText: text, decodedText: decoded, encoding: 'hex' };
    } else if (/^[A-Za-z0-9+/=]+$/.test(text) && text.length % 4 === 0) {
      // Decode as base64
      try {
        const decoded = Buffer.from(text, 'base64').toString();
        // Only return if the decoded text looks meaningful (contains ASCII)
        if (/^[\x20-\x7E\t\n\r]+$/.test(decoded)) {
          return { originalText: text, decodedText: decoded, encoding: 'base64' };
        }
      } catch (e) {
        // Ignore decoding errors
      }
    }
    
    // Try additional decoding methods
    
    // ROT13 (simple Caesar cipher)
    if (/^[A-Za-z]+$/.test(text)) {
      const rot13 = text.replace(/[a-zA-Z]/g, function(c) {
        return String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
      });
      // Only return if the decoded text looks different from the original
      if (rot13 !== text) {
        return { originalText: text, decodedText: rot13, encoding: 'rot13' };
      }
    }
    
    // Try XOR with common keys (1, 2, 3, 0xFF)
    const commonKeys = [1, 2, 3, 0xFF];
    for (const key of commonKeys) {
      if (text.length > 0) {
        const bytes = Buffer.from(text);
        const xored = Buffer.alloc(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
          xored[i] = bytes[i] ^ key;
        }
        const xoredText = xored.toString();
        // Check if result is printable ASCII
        if (/^[\x20-\x7E\t\n\r]+$/.test(xoredText)) {
          return { originalText: text, decodedText: xoredText, encoding: `XOR-${key.toString(16)}` };
        }
      }
    }
  } catch (e) {
    // Ignore any decoding errors
    console.log(`Error in decodeText: ${e.message}`);
  }
  return null;
}

// Detect PDF encryption method
async function detectEncryption(pdfDocument) {
  try {
    const encryptInfo = {
      isEncrypted: false,
      encryptionMethod: ENCRYPTION_METHODS.NONE,
      details: {}
    };
    
    // Check if PDF has encryption info in metadata
    try {
      const metadata = await pdfDocument.getMetadata();
      if (metadata && metadata.info) {
        if (metadata.info.IsEncrypted) {
          encryptInfo.isEncrypted = true;
        }
        
        if (metadata.info.EncryptFilterName) {
          encryptInfo.encryptionMethod = metadata.info.EncryptFilterName;
          encryptInfo.details.filterName = metadata.info.EncryptFilterName;
        }
      }
    } catch (err) {
      console.log(`Error checking metadata for encryption: ${err.message}`);
    }
    
    // Try to access PDF internals for encryption info
    if (pdfDocument._pdfInfo && pdfDocument._pdfInfo.encrypt) {
      encryptInfo.isEncrypted = true;
      const encrypt = pdfDocument._pdfInfo.encrypt;
      
      encryptInfo.details = {
        ...encryptInfo.details,
        streamMethod: encrypt.streamMethod,
        stringMethod: encrypt.stringMethod,
        userPermissions: encrypt.userPermissions
      };
      
      // Determine encryption method based on internal values
      if (encrypt.algorithm) {
        if (encrypt.algorithm.includes('RC4')) {
          encryptInfo.encryptionMethod = ENCRYPTION_METHODS.RC4;
        } else if (encrypt.algorithm.includes('AES')) {
          encryptInfo.encryptionMethod = ENCRYPTION_METHODS.AES;
        } else if (encrypt.algorithm === 'Identity') {
          encryptInfo.encryptionMethod = ENCRYPTION_METHODS.IDENTITY;
        } else {
          encryptInfo.encryptionMethod = ENCRYPTION_METHODS.CUSTOM;
          encryptInfo.details.customAlgorithm = encrypt.algorithm;
        }
      } else if (encryptInfo.isEncrypted) {
        encryptInfo.encryptionMethod = ENCRYPTION_METHODS.UNKNOWN;
      }
    }
    
    return encryptInfo;
  } catch (err) {
    console.log(`Error detecting encryption: ${err.message}`);
    return {
      isEncrypted: false,
      encryptionMethod: ENCRYPTION_METHODS.UNKNOWN,
      details: { error: err.message }
    };
  }
}

/**
 * Extract all content from PDF document
 */
async function extractPDFContent(pdfPath, outputDir = './') {
  console.log(`Processing PDF: ${pdfPath}`);
  
  if (!fs.existsSync(pdfPath)) {
    console.error(`Error: File ${pdfPath} does not exist.`);
    process.exit(1);
  }
  
  // Create output directory if it doesn't exist
  const extractionDir = path.join(path.dirname(pdfPath), outputDir);
  if (!fs.existsSync(extractionDir)) {
    fs.mkdirSync(extractionDir, { recursive: true });
    console.log(`Created output directory: ${extractionDir}`);
  }
  
  const pdfFilename = path.basename(pdfPath, path.extname(pdfPath));
  
  try {
    // Read the PDF file
    const data = new Uint8Array(fs.readFileSync(pdfPath));
    
    // Load the PDF document with optional password
    const loadingTask = pdfjsLib.getDocument({
      data,
      password,
      disableWorker: true, // Disable worker to avoid configuration issues
      canvasFactory: {
        create: function(width, height) {
          let canvas = new Canvas(width, height);
          return {
            canvas: canvas,
            context: canvas.getContext('2d'),
          };
        },
        reset: function(canvasAndContext, width, height) {
          canvasAndContext.canvas.width = width;
          canvasAndContext.canvas.height = height;
        },
        destroy: function(canvasAndContext) {
          // Node canvas doesn't need explicit destruction
          // This method is required by PDF.js but we can leave it empty
        }
      }
    });
    
    // Handle password protection and loading errors
    const pdfDocument = await loadingTask.promise.catch(error => {
      if (error instanceof pdfjsLib.PasswordException) {
        if (error.code === pdfjsLib.PasswordResponses.NEED_PASSWORD) {
          console.error('Error: This PDF is password protected. Please provide a password using the -p option.');
        } else if (error.code === pdfjsLib.PasswordResponses.INCORRECT_PASSWORD) {
          console.error('Error: Incorrect password provided for this PDF.');
        }
        process.exit(1);
      }
      throw error;
    });
    
    console.log(`PDF document loaded. Number of pages: ${pdfDocument.numPages}`);
    
    // Detect encryption method
    const encryptionInfo = await detectEncryption(pdfDocument);
    console.log('\n===== ENCRYPTION INFORMATION =====');
    if (encryptionInfo.isEncrypted) {
      console.log(`PDF is encrypted using: ${encryptionInfo.encryptionMethod}`);
      console.log('Encryption details:', JSON.stringify(encryptionInfo.details, null, 2));
    } else {
      console.log('PDF is not encrypted.');
    }
    
    // Save encryption info
    const encryptionFilename = `${pdfFilename}_encryption_info.json`;
    const encryptionPath = path.join(extractionDir, encryptionFilename);
    fs.writeFileSync(encryptionPath, JSON.stringify(encryptionInfo, null, 2));
    console.log(`Encryption information saved to: ${encryptionPath}`);
    
    // Save PDF structure overview
    const structureOverview = {
      filename: pdfPath,
      numPages: pdfDocument.numPages,
      encryption: encryptionInfo,
      extractedFiles: [encryptionPath]
    };

    // Process each page
    for (let pageNum = 1; pageNum <= pdfDocument.numPages; pageNum++) {
      console.log(`\n===== PAGE ${pageNum} =====`);
      const page = await pdfDocument.getPage(pageNum);
      
      // Get page info
      const viewport = page.getViewport({ scale: 1.0 });
      console.log(`Page dimensions: ${viewport.width} x ${viewport.height}`);
      
      // Create an extended viewport that's larger than the page to capture out-of-bounds text
      const extendedViewport = {
        viewBox: [
          -viewport.width, // Allow negative x coordinates
          -viewport.height * 2, // Allow large negative y coordinates (for text below the page)
          viewport.width * 3, // Make the width 3x normal to capture text far to the right
          viewport.height * 3  // Make the height 3x normal
        ]
      };

      // Extract text content nodes
      const textContent = await page.getTextContent({ 
        normalizeWhitespace: false,
        disableCombineTextItems: false,
        includeMarkedContent: true,
        viewport: extendedViewport
      });
      console.log('\n--- Text Content Nodes ---');
      if (textContent.items.length > 0) {
        textContent.items.forEach((item, index) => {
          if (item.str) {
            console.log(`Text Node ${index + 1}: "${item.str}" [x: ${item.transform?.[4]?.toFixed(2) || 'N/A'}, y: ${item.transform?.[5]?.toFixed(2) || 'N/A'}]`);
            
            // Check if text might be encoded/encrypted
            const decodedResult = decodeText(item.str);
            if (decodedResult) {
              console.log(`  Decoded (${decodedResult.encoding}): "${decodedResult.decodedText}"`);
              
              // Save decoded text
              const decodedFilename = `${pdfFilename}_page${pageNum}_decoded_text_${index + 1}.txt`;
              const decodedPath = path.join(extractionDir, decodedFilename);
              fs.writeFileSync(decodedPath, `Original (${decodedResult.encoding}): ${decodedResult.originalText}\nDecoded: ${decodedResult.decodedText}`);
              console.log(`  Decoded text saved to: ${decodedPath}`);
              structureOverview.extractedFiles.push(decodedPath);
            }
          } else {
            console.log(`Text Node ${index + 1}: [Empty or non-text node]`);
          }
        });
      } else {
        console.log('No text content found on this page.');
      }
      
      // Extract annotations
      try {
        const annotations = await page.getAnnotations();
        console.log('\n--- Annotation Nodes ---');
        if (annotations.length > 0) {
          for (let i = 0; i < annotations.length; i++) {
            const annotation = annotations[i];
            console.log(`Annotation ${i + 1}:`);
            console.log(`  Type: ${annotation.subtype || 'Unknown'}`);
            
            if (annotation.rect) {
              console.log(`  Rect: [${annotation.rect.join(', ')}]`);
            }
            
            // Print content if available and human-readable
            if (annotation.contents && typeof annotation.contents === 'string') {
              console.log(`  Content: "${annotation.contents}"`);
              
              // Check if content might be encoded/encrypted
              const decodedResult = decodeText(annotation.contents);
              if (decodedResult) {
                console.log(`  Decoded (${decodedResult.encoding}): "${decodedResult.decodedText}"`);
                
                // Save decoded text
                const decodedFilename = `${pdfFilename}_page${pageNum}_annotation${i + 1}_decoded.txt`;
                const decodedPath = path.join(extractionDir, decodedFilename);
                fs.writeFileSync(decodedPath, `Original (${decodedResult.encoding}): ${decodedResult.originalText}\nDecoded: ${decodedResult.decodedText}`);
                console.log(`  Decoded annotation saved to: ${decodedPath}`);
                structureOverview.extractedFiles.push(decodedPath);
              }
            }
            
            // Check for JavaScript actions in annotations
            if (annotation.action) {
              console.log(`  Action type: ${annotation.action.type || 'Unknown'}`);
              
              if (annotation.action.type === 'JavaScript' && annotation.action.js) {
                console.log(`  JavaScript action found: "${annotation.action.js.substring(0, 50)}..."`);
                
                // Save JavaScript code
                const jsFilename = `${pdfFilename}_page${pageNum}_annotation${i + 1}_javascript.js`;
                const jsPath = path.join(extractionDir, jsFilename);
                fs.writeFileSync(jsPath, annotation.action.js);
                console.log(`  JavaScript code saved to: ${jsPath}`);
                structureOverview.extractedFiles.push(jsPath);
              }
            }
            
            // Extract file attachments or embedded files
            if (annotation.file) {
              const fileData = annotation.file;
              const filename = `${pdfFilename}_page${pageNum}_annotation${i + 1}_${annotation.filename || 'attachment.bin'}`;
              const filePath = path.join(extractionDir, filename);
              
              fs.writeFileSync(filePath, Buffer.from(fileData));
              console.log(`  Extracted file attachment to: ${filePath}`);
              structureOverview.extractedFiles.push(filePath);
            }
            
            // Extract form data if available
            if (annotation.fieldType) {
              console.log(`  Form field type: ${annotation.fieldType}`);
              console.log(`  Form field value: ${annotation.fieldValue}`);
            }
            
            // Print other potentially useful properties
            if (annotation.url) {
              console.log(`  URL: ${annotation.url}`);
            }
            
            if (annotation.title) {
              console.log(`  Title: ${annotation.title}`);
            }
          }
        } else {
          console.log('No annotations found on this page.');
        }
      } catch (err) {
        console.log(`  Error fetching annotations: ${err.message}`);
      }
      
      // Extract page objects and operations in a safer way
      try {
        console.log('\n--- Page Objects and Operations ---');
        // Get the operator list to find all the operations
        const opList = await page.getOperatorList();
        console.log(`  Total operations: ${opList.fnArray.length}`);
        
        // Extract operator list to JSON for analysis
        const operatorFilename = `${pdfFilename}_page${pageNum}_operators.json`;
        const operatorPath = path.join(extractionDir, operatorFilename);
        
        // Create a serializable version of the operator list
        const serializableOpList = {
          fnArray: Array.from(opList.fnArray),
          argsArray: opList.argsArray.map(args => {
            try {
              // Try to clone objects for better serialization
              return JSON.parse(JSON.stringify(args));
            } catch (e) {
              // If can't serialize, return simple representation
              return Array.isArray(args) ? 
                args.map(arg => typeof arg === 'object' ? '[Complex Object]' : arg) : 
                '[Unserializable Args]';
            }
          })
        };
        
        fs.writeFileSync(operatorPath, JSON.stringify(serializableOpList, null, 2));
        console.log(`  Operator list saved to: ${operatorPath}`);
        structureOverview.extractedFiles.push(operatorPath);
        
        // Render page to a buffer for extraction and visualization
        try {
          const canvas = new Canvas(viewport.width, viewport.height);
          const ctx = canvas.getContext('2d');
          
          await page.render({
            canvasContext: ctx,
            viewport: viewport
          }).promise;
          
          // Save the rendered page as PNG
          const pageImageFilename = `${pdfFilename}_page${pageNum}_rendered.png`;
          const pageImagePath = path.join(extractionDir, pageImageFilename);
          fs.writeFileSync(pageImagePath, canvas.toBuffer('image/png'));
          console.log(`  Full page rendered to: ${pageImagePath}`);
          structureOverview.extractedFiles.push(pageImagePath);
        } catch (renderErr) {
          console.log(`  Error rendering page: ${renderErr.message}`);
        }
      } catch (err) {
        console.log(`  Error accessing page objects: ${err.message}`);
      }
      
      // Try to extract document stream data
      try {
        console.log('\n--- Raw Content Streams ---');
        
        // Extract raw content stream - a more direct approach
        // This is a specific way to get the raw content stream that works in Node.js
        const pageRef = page._pageInfo.ref;
        if (pageRef) {
          const streamFilename = `${pdfFilename}_page${pageNum}_raw_content.bin`;
          const streamPath = path.join(extractionDir, streamFilename);
          
          // Write the page reference info to help with external tools
          const pageRefFilename = `${pdfFilename}_page${pageNum}_ref.json`;
          const pageRefPath = path.join(extractionDir, pageRefFilename);
          fs.writeFileSync(pageRefPath, JSON.stringify(pageRef, null, 2));
          console.log(`  Page reference data saved to: ${pageRefPath}`);
          structureOverview.extractedFiles.push(pageRefPath);
          
          // Try to extract content streams more directly
          try {
            if (page._pageInfo.xref && page._pageInfo.objId) {
              const pageDict = await page._pageInfo.xref.fetch(page._pageInfo.objId);
              
              if (pageDict.has('Contents')) {
                const contents = await pageDict.get('Contents');
                
                // Handle both single and array of content streams
                const contentStreams = Array.isArray(contents) ? contents : [contents];
                
                for (let i = 0; i < contentStreams.length; i++) {
                  const result = await extractStreamContent(
                    contentStreams[i], 
                    pdfFilename, 
                    pageNum, 
                    i, 
                    extractionDir, 
                    structureOverview
                  );
                  
                  if (result) {
                    console.log(`  Content stream ${i + 1} decoded using ${result.method}: ${result.path}`);
                  }
                }
              }
            }
          } catch (contentsErr) {
            console.log(`  Error extracting detailed content streams: ${contentsErr.message}`);
          }
          
          console.log(`  Note: To extract actual raw stream content, you may also need to use a specialized PDF parsing tool like QPDF or pdftk.`);
        } else {
          console.log(`  Could not access page reference information for raw content extraction.`);
        }
      } catch (err) {
        console.log(`  Error accessing raw content streams: ${err.message}`);
      }
      
      // Try to extract hidden text (OCR text layers, etc)
      try {
        const textContent = await page.getTextContent({ normalizeWhitespace: false, includeMarkedContent: true });
        
        // Extract marked content which may include hidden text
        const markedContentFilename = `${pdfFilename}_page${pageNum}_marked_content.json`;
        const markedContentPath = path.join(extractionDir, markedContentFilename);
        fs.writeFileSync(markedContentPath, JSON.stringify(textContent, null, 2));
        console.log(`  Marked content saved to: ${markedContentPath}`);
        structureOverview.extractedFiles.push(markedContentPath);
      } catch (err) {
        console.log(`  Error extracting marked content: ${err.message}`);
      }
      
      // Extract text operators directly from PDF.js
      await extractTextOperatorsFromPage(page, pageNum, extractionDir, pdfFilename, structureOverview);
    }
    
    // Try to get document metadata
    try {
      const metadata = await pdfDocument.getMetadata();
      console.log('\n===== DOCUMENT METADATA =====');
      if (metadata) {
        console.log(JSON.stringify(metadata.info, null, 2));
        
        // Save metadata to file
        const metadataFilename = `${pdfFilename}_metadata.json`;
        const metadataPath = path.join(extractionDir, metadataFilename);
        fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
        console.log(`Metadata saved to: ${metadataPath}`);
        structureOverview.extractedFiles.push(metadataPath);
        
        // Extract XMP metadata if available
        if (metadata.metadata && metadata.metadata.rawData) {
          const xmpFilename = `${pdfFilename}_xmp_metadata.xml`;
          const xmpPath = path.join(extractionDir, xmpFilename);
          fs.writeFileSync(xmpPath, metadata.metadata.rawData);
          console.log(`XMP metadata saved to: ${xmpPath}`);
          structureOverview.extractedFiles.push(xmpPath);
        }
      }
    } catch (err) {
      console.log(`Error extracting metadata: ${err.message}`);
    }
    
    // Try to get document outline
    try {
      const outline = await pdfDocument.getOutline();
      console.log('\n===== DOCUMENT OUTLINE =====');
      if (outline && outline.length > 0) {
        printOutlineItems(outline);
        
        // Save outline to file
        const outlineFilename = `${pdfFilename}_outline.json`;
        const outlinePath = path.join(extractionDir, outlineFilename);
        fs.writeFileSync(outlinePath, JSON.stringify(outline, null, 2));
        console.log(`Outline saved to: ${outlinePath}`);
        structureOverview.extractedFiles.push(outlinePath);
      } else {
        console.log('No document outline/bookmarks found.');
      }
    } catch (err) {
      console.log(`Error extracting outline: ${err.message}`);
    }
    
    // Try to extract attachments from document level
    try {
      console.log('\n===== DOCUMENT ATTACHMENTS =====');
      const attachments = await pdfDocument.getAttachments().catch(() => null);
      
      if (attachments && Object.keys(attachments).length > 0) {
        for (const [filename, attachment] of Object.entries(attachments)) {
          const attachmentFilename = `${pdfFilename}_attachment_${filename}`;
          const attachmentPath = path.join(extractionDir, attachmentFilename);
          
          fs.writeFileSync(attachmentPath, Buffer.from(attachment.content));
          console.log(`Attachment extracted to: ${attachmentPath}`);
          structureOverview.extractedFiles.push(attachmentPath);
        }
      } else {
        console.log('No document attachments found.');
      }
    } catch (err) {
      console.log(`Error extracting attachments: ${err.message}`);
    }
    
    // Save extraction summary
    const summaryFilename = `${pdfFilename}_extraction_summary.json`;
    const summaryPath = path.join(extractionDir, summaryFilename);
    fs.writeFileSync(summaryPath, JSON.stringify(structureOverview, null, 2));
    console.log(`\nExtraction summary saved to: ${summaryPath}`);
    
    console.log(`\nAll extractable content has been saved to: ${extractionDir}`);
    
  } catch (error) {
    console.error('Error processing PDF:', error);
    process.exit(1);
  }
}

// Process content streams with potential decryption
async function processStreamData(streamData, filename, extractionDir, structureOverview) {
  // Save raw stream data (always save this regardless of content)
  const rawFilename = `${filename}_raw.bin`;
  const rawPath = path.join(extractionDir, rawFilename);
  fs.writeFileSync(rawPath, Buffer.from(streamData));
  structureOverview.extractedFiles.push(rawPath);
  
  // Try multiple string decodings to find PDF operators
  const encodings = ['latin1', 'ascii', 'utf8', 'utf16le'];
  let foundOperators = false;
  
  for (const encoding of encodings) {
    try {
      const streamText = Buffer.from(streamData).toString(encoding);
      
      // Look for common PDF text operators (more comprehensive detection)
      if ((streamText.includes('BT') && streamText.includes('ET')) || 
          streamText.includes('Tf') || 
          streamText.includes('Td') || 
          streamText.includes('TJ') || 
          streamText.includes('Tj')) {
        
        // Save the raw operators text
        const operatorsFilename = `${filename}_operators_${encoding}.txt`;
        const operatorsPath = path.join(extractionDir, operatorsFilename);
        fs.writeFileSync(operatorsPath, streamText);
        structureOverview.extractedFiles.push(operatorsPath);
        
        console.log(`  Found PDF text operators in ${encoding} encoding`);
        
        // Try to interpret the text operators
        const interpreted = interpretTextOperators(streamText);
        if (interpreted) {
          const interpretedFilename = `${filename}_interpreted.json`;
          const interpretedPath = path.join(extractionDir, interpretedFilename);
          fs.writeFileSync(interpretedPath, JSON.stringify(interpreted, null, 2));
          structureOverview.extractedFiles.push(interpretedPath);
          foundOperators = true;
          // Don't return yet - try all encodings and collect all results
        }
      }
    } catch (err) {
      // Just continue to next encoding on error
    }
  }
  
  if (foundOperators) {
    return { decodedText: "PDF Text Operators", method: 'pdf-operators', path: rawPath };
  }
  
  // Continue with other decoding methods as before...
  // Try to interpret as PDF operators if it contains operator signatures
  const streamText = Buffer.from(streamData).toString('latin1');
  if (streamText.includes('BT') && (streamText.includes('TJ') || streamText.includes('Tj') || streamText.includes('Td'))) {
    const operatorsFilename = `${filename}_operators.txt`;
    const operatorsPath = path.join(extractionDir, operatorsFilename);
    fs.writeFileSync(operatorsPath, streamText);
    structureOverview.extractedFiles.push(operatorsPath);
    
    // Try to interpret the text operators
    const interpreted = interpretTextOperators(streamText);
    if (interpreted) {
      const interpretedFilename = `${filename}_interpreted.json`;
      const interpretedPath = path.join(extractionDir, interpretedFilename);
      fs.writeFileSync(interpretedPath, JSON.stringify(interpreted, null, 2));
      structureOverview.extractedFiles.push(interpretedPath);
      return { decodedText: streamText, method: 'pdf-operators', path: operatorsPath, interpreted: interpretedPath };
    }
  }
  
  // Try to decode as text with standard UTF-8 encoding
  try {
    const textDecoder = new TextDecoder('utf-8');
    const textContent = textDecoder.decode(streamData);
    
    // If the content looks like text, save it separately
    if (/[\x20-\x7E\t\n\r]/.test(textContent)) {
      const textFilename = `${filename}_decoded_utf8.txt`;
      const textPath = path.join(extractionDir, textFilename);
      fs.writeFileSync(textPath, textContent);
      structureOverview.extractedFiles.push(textPath);
      return { decodedText: textContent, method: 'utf-8', path: textPath };
    }
  } catch (err) {
    console.log(`Error decoding as UTF-8: ${err.message}`);
  }
  
  // Try XOR decryption with common keys
  const commonKeys = [1, 2, 3, 0xFF, 0x7F, 0x0F, 0xF0];
  for (const key of commonKeys) {
    try {
      const xored = Buffer.alloc(streamData.length);
      for (let i = 0; i < streamData.length; i++) {
        xored[i] = streamData[i] ^ key;
      }
      
      // Check if XOR result looks like text
      const xoredText = xored.toString('utf-8');
      if (/^[\x20-\x7E\t\n\r]+$/.test(xoredText.substring(0, Math.min(100, xoredText.length)))) {
        const xorFilename = `${filename}_xor_0x${key.toString(16)}.txt`;
        const xorPath = path.join(extractionDir, xorFilename);
        fs.writeFileSync(xorPath, xoredText);
        structureOverview.extractedFiles.push(xorPath);
        return { decodedText: xoredText, method: `XOR-0x${key.toString(16)}`, path: xorPath };
      }
    } catch (err) {
      console.log(`Error with XOR-${key} decryption: ${err.message}`);
    }
  }
  
  // Try RC4 decryption with common keys
  try {
    const commonPasswords = ['test', 'password', '123456', 'admin'];
    for (const password of commonPasswords) {
      const key = crypto.createHash('md5').update(password).digest();
      
      try {
        // Create RC4 cipher with the key
        const cipher = crypto.createCipheriv('rc4', key, '');
        cipher.setAutoPadding(false);
        
        let rc4Data = cipher.update(Buffer.from(streamData));
        rc4Data = Buffer.concat([rc4Data, cipher.final()]);
        
        // Check if result looks like text
        const rc4Text = rc4Data.toString('utf-8');
        if (/^[\x20-\x7E\t\n\r]+$/.test(rc4Text.substring(0, Math.min(100, rc4Text.length)))) {
          const rc4Filename = `${filename}_rc4_${password}.txt`;
          const rc4Path = path.join(extractionDir, rc4Filename);
          fs.writeFileSync(rc4Path, rc4Text);
          structureOverview.extractedFiles.push(rc4Path);
          return { decodedText: rc4Text, method: `RC4-${password}`, path: rc4Path };
        }
      } catch (err) {
        // Ignore individual cipher errors
      }
    }
  } catch (err) {
    console.log(`Error with RC4 decryption: ${err.message}`);
  }
  
  // Try various text encodings
  const textEncodings = ['latin1', 'ascii', 'utf16le'];
  for (const encoding of textEncodings) {
    try {
      const decoded = Buffer.from(streamData).toString(encoding);
      if (/^[\x20-\x7E\t\n\r]+$/.test(decoded.substring(0, Math.min(100, decoded.length)))) {
        const encFilename = `${filename}_${encoding}.txt`;
        const encPath = path.join(extractionDir, encFilename);
        fs.writeFileSync(encPath, decoded);
        structureOverview.extractedFiles.push(encPath);
        return { decodedText: decoded, method: encoding, path: encPath };
      }
    } catch (err) {
      console.log(`Error with ${encoding} decoding: ${err.message}`);
    }
  }
  
  return null;
}

// Extract streams with more advanced handling
async function extractStreamContent(stream, baseFilename, pageNum, i, extractionDir, structureOverview) {
  try {
    if (!stream || !(stream instanceof pdfjsLib.PDFStream)) {
      return null;
    }
    
    console.log(`  Extracting content stream ${i + 1}`);
    
    // Get stream data
    const streamData = await stream.getBytes();
    const contentFilename = `${baseFilename}_page${pageNum}_content_stream_${i + 1}`;
    
    // Also save the raw unprocessed stream directly
    const rawStreamFilename = `${contentFilename}_raw.bin`;
    const rawStreamPath = path.join(extractionDir, rawStreamFilename);
    fs.writeFileSync(rawStreamPath, Buffer.from(streamData));
    structureOverview.extractedFiles.push(rawStreamPath);
    
    // Save raw text representation (similar to what test.py does)
    try {
      const decompressionAttempts = [
        () => streamData, // Raw as-is
        () => zlib.inflateSync(streamData), // zlib decompression
        () => Buffer.from(streamData).toString('utf8'), // UTF-8 decoding
        () => Buffer.from(streamData).toString('latin1') // Latin1 decoding
      ];
      
      for (let j = 0; j < decompressionAttempts.length; j++) {
        try {
          const decompressed = decompressionAttempts[j]();
          const rawTextFilename = `${contentFilename}_raw_attempt${j + 1}.txt`;
          const rawTextPath = path.join(extractionDir, rawTextFilename);
          
          if (Buffer.isBuffer(decompressed)) {
            // Check if it contains text operator patterns
            const textContents = decompressed.toString('latin1');
            if (textContents.includes('BT') || textContents.includes('TJ') || 
                textContents.includes('Tf') || textContents.includes('Td')) {
              fs.writeFileSync(rawTextPath, textContents);
              structureOverview.extractedFiles.push(rawTextPath);
              console.log(`  Saved raw text stream (attempt ${j + 1})`);
            }
          } else if (typeof decompressed === 'string') {
            // Already a string
            if (decompressed.includes('BT') || decompressed.includes('TJ') || 
                decompressed.includes('Tf') || decompressed.includes('Td')) {
              fs.writeFileSync(rawTextPath, decompressed);
              structureOverview.extractedFiles.push(rawTextPath);
              console.log(`  Saved raw text stream (attempt ${j + 1})`);
            }
          }
        } catch (err) {
          // Ignore errors and try next method
        }
      }
    } catch (err) {
      console.log(`  Error extracting raw stream text: ${err.message}`);
    }
    
    // Process and try to decrypt the stream data
    return await processStreamData(streamData, contentFilename, extractionDir, structureOverview);
  } catch (streamErr) {
    console.log(`  Error extracting content stream ${i + 1}: ${streamErr.message}`);
    return null;
  }
}

// Function to extract FlateDecode streams directly from PDF file (like test.py)
async function extractRawPdfStreams(pdfPath, outputDir) {
  console.log(`Extracting raw streams directly from PDF file: ${pdfPath}`);
  
  // Create output directory if it doesn't exist
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  try {
    // Read PDF file as binary
    const pdfData = fs.readFileSync(pdfPath);
    
    // Convert to string for regex matching
    const pdfDataString = pdfData.toString('binary');
    
    // Create a regex to find FlateDecode streams, similar to test.py
    // This is more similar to the Python regex: rb'.*?FlateDecode.*?stream(.*?)endstream'
    const streamRegex = /.*?FlateDecode.*?stream([\s\S]*?)endstream/g;
    
    let match;
    let streamCount = 0;
    
    // Process all found streams
    while ((match = streamRegex.exec(pdfDataString)) !== null) {
      streamCount++;
      
      try {
        // Extract the stream content
        let streamContent = match[1];
        
        // Remove leading \r\n or \n (whitespace after 'stream')
        if (streamContent.startsWith('\r\n')) {
          streamContent = streamContent.slice(2);
        } else if (streamContent.startsWith('\n')) {
          streamContent = streamContent.slice(1);
        }
        
        // Convert stream content to buffer for processing
        const streamBuffer = Buffer.from(streamContent, 'binary');
        
        // Save raw stream
        const rawFilename = path.join(outputDir, `raw_stream_${streamCount}.bin`);
        fs.writeFileSync(rawFilename, streamBuffer);
        
        // Try to decompress with zlib
        try {
          const decompressed = zlib.inflateSync(streamBuffer);
          
          // Convert to string in various encodings
          const utf8Content = decompressed.toString('utf8');
          const latin1Content = decompressed.toString('latin1');
          
          // Always save the decompressed content for analysis
          fs.writeFileSync(path.join(outputDir, `decompressed_stream_${streamCount}.txt`), latin1Content);
          
          // Check if it contains PDF operators
          const hasPdfOperators = latin1Content.includes('BT') && 
                                 (latin1Content.includes('TJ') || 
                                  latin1Content.includes('Tj') || 
                                  latin1Content.includes('Td'));
          
          if (hasPdfOperators) {
            // Save the operator content
            const operatorsFilename = path.join(outputDir, `pdf_operators_${streamCount}.txt`);
            fs.writeFileSync(operatorsFilename, latin1Content);
            console.log(`Found PDF text operators in stream ${streamCount}`);
          } else {
            // Check if it's readable text
            const isText = /[\x20-\x7E\t\n\r]{10,}/.test(latin1Content);
            if (isText) {
              const textFilename = path.join(outputDir, `text_stream_${streamCount}.txt`);
              fs.writeFileSync(textFilename, latin1Content);
            }
          }
        } catch (inflateErr) {
          console.log(`Error decompressing stream ${streamCount}: ${inflateErr.message}`);
        }
      } catch (streamErr) {
        console.log(`Error processing stream ${streamCount}: ${streamErr.message}`);
      }
      
      // Move past this stream for the next iteration
      streamRegex.lastIndex = streamRegex.lastIndex + 1;
    }
    
    console.log(`Extracted ${streamCount} raw streams from PDF file.`);
    return streamCount;
  } catch (err) {
    console.error(`Error extracting raw streams: ${err.message}`);
    return 0;
  }
}

// Add a simple direct extractor that closely mimics the Python approach
function extractPdfStreamsDirectly(pdfPath, outputDir) {
  console.log(`\nExtracting PDF streams directly (Python-style approach)...`);
  
  // Create output directory if it doesn't exist
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  try {
    // Read the PDF as a raw buffer (equivalent to Python's binary read)
    const pdfBuffer = fs.readFileSync(pdfPath);
    
    // Convert to string for pattern matching
    const pdfStr = pdfBuffer.toString('binary');
    
    // Find all occurrences of 'FlateDecode' followed by 'stream' and ending with 'endstream'
    // Using a simplified approach similar to Python's regex
    let streamCount = 0;
    let startIdx = 0;
    
    while (true) {
      // Find the next potential stream
      const flatIndex = pdfStr.indexOf('FlateDecode', startIdx);
      if (flatIndex === -1) break;
      
      const streamIndex = pdfStr.indexOf('stream', flatIndex);
      if (streamIndex === -1) break;
      
      const endstreamIndex = pdfStr.indexOf('endstream', streamIndex);
      if (endstreamIndex === -1) break;
      
      // Extract the content between 'stream' and 'endstream'
      let streamContent = pdfStr.substring(streamIndex + 6, endstreamIndex);
      
      // Adjust for the newline after 'stream' (similar to Python script)
      if (streamContent.startsWith('\r\n')) {
        streamContent = streamContent.substring(2);
      } else if (streamContent.startsWith('\n')) {
        streamContent = streamContent.substring(1);
      }
      
      // Convert string back to buffer for zlib decompression
      const streamBuffer = Buffer.from(streamContent, 'binary');
      
      streamCount++;
      console.log(`Found stream ${streamCount} (${streamBuffer.length} bytes)`);
      
      // Save the raw stream for reference
      const rawStreamPath = path.join(outputDir, `direct_raw_stream_${streamCount}.bin`);
      fs.writeFileSync(rawStreamPath, streamBuffer);
      
      // Try to decompress using zlib (like in Python)
      try {
        const decompressed = zlib.inflateSync(streamBuffer);
        const decompressedText = decompressed.toString('latin1');
        
        // Save the decompressed content
        const decompressedPath = path.join(outputDir, `direct_stream_${streamCount}.txt`);
        fs.writeFileSync(decompressedPath, decompressedText);
        
        // Check if it's a text operator stream
        if (decompressedText.includes('BT') && 
            (decompressedText.includes('TJ') || 
             decompressedText.includes('Tj') || 
             decompressedText.includes('Td'))) {
          console.log(`  Stream ${streamCount} contains PDF text operators!`);
          const operatorsPath = path.join(outputDir, `direct_operators_${streamCount}.txt`);
          fs.writeFileSync(operatorsPath, decompressedText);
        }
      } catch (error) {
        console.log(`  Failed to decompress stream ${streamCount}: ${error.message}`);
      }
      
      // Move past this stream for the next iteration
      startIdx = endstreamIndex + 9; // length of 'endstream'
    }
    
    console.log(`Direct extraction found ${streamCount} streams`);
    return streamCount;
  } catch (error) {
    console.error(`Error in direct extraction: ${error.message}`);
    return 0;
  }
}

// Function to parse and interpret PDF text operators from a stream
function interpretTextOperators(streamText) {
  try {
    // Helper to extract text from TJ arrays
    const extractTJText = (tjArray) => {
      if (!tjArray || !tjArray.startsWith('[') || !tjArray.endsWith(']')) return null;
      
      // Extract the content between brackets, handling nested structures
      const content = tjArray.substring(1, tjArray.length - 1);
      
      // Parse the TJ array content
      let result = '';
      let currentString = '';
      let inString = false;
      let depth = 0;
      
      for (let i = 0; i < content.length; i++) {
        const char = content[i];
        
        if (char === '(' && !inString) {
          inString = true;
          currentString = '';
        } else if (char === ')' && inString) {
          inString = false;
          result += currentString;
        } else if (inString) {
          // Handle escaped characters in the string
          if (char === '\\' && i + 1 < content.length) {
            const nextChar = content[i + 1];
            // Handle common PDF string escape sequences
            if (nextChar === 'n') currentString += '\n';
            else if (nextChar === 'r') currentString += '\r';
            else if (nextChar === 't') currentString += '\t';
            else if (nextChar === 'b') currentString += '\b';
            else if (nextChar === 'f') currentString += '\f';
            else if (nextChar === '\\') currentString += '\\';
            else if (nextChar === '(') currentString += '(';
            else if (nextChar === ')') currentString += ')';
            else if (/[0-7]{1,3}/.test(content.substring(i+1, i+4))) {
              // Octal escape sequence \ddd
              const octal = content.substring(i+1, i+4).match(/[0-7]{1,3}/)[0];
              currentString += String.fromCharCode(parseInt(octal, 8));
              i += octal.length;
            } else {
              currentString += nextChar; // Just add the escaped character
            }
            i++; // Skip the next character as it's part of the escape sequence
          } else {
            currentString += char;
          }
        }
        // Skip numeric kerning values
      }
      
      return result;
    };
    
    // Split the stream into operations
    const operations = [];
    let currentOp = '';
    let textBlockStack = [];
    let currentTextBlock = null;
    
    // Split the stream by operators
    const operationRegex = /\/(F\d+)\s+([\d.]+)\s+Tf|(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+Td|\[(.*?)\]TJ|BT|ET/g;
    let match;
    let lastIndex = 0;
    
    while ((match = operationRegex.exec(streamText)) !== null) {
      const fullMatch = match[0];
      const fontMatch = match[1];
      const fontSizeMatch = match[2];
      const xPosMatch = match[3];
      const yPosMatch = match[4];
      const tjContentMatch = match[5];
      
      if (fullMatch === 'BT') {
        // Begin text object
        currentTextBlock = {
          type: 'TextBlock',
          font: null,
          fontSize: null,
          positions: [],
          textFragments: []
        };
        textBlockStack.push(currentTextBlock);
        operations.push({
          operator: 'BT',
          description: 'Begin Text Object'
        });
      } else if (fullMatch === 'ET') {
        // End text object
        if (textBlockStack.length > 0) {
          const completedTextBlock = textBlockStack.pop();
          currentTextBlock = textBlockStack.length > 0 ? textBlockStack[textBlockStack.length - 1] : null;
          
          // Add the complete text block to operations
          operations.push({
            operator: 'ET',
            description: 'End Text Object',
            textBlock: completedTextBlock
          });
        }
      } else if (fontMatch && fontSizeMatch) {
        // Font setting
        if (currentTextBlock) {
          currentTextBlock.font = fontMatch;
          currentTextBlock.fontSize = parseFloat(fontSizeMatch);
        }
        operations.push({
          operator: 'Tf',
          description: 'Set Font and Size',
          font: fontMatch,
          fontSize: parseFloat(fontSizeMatch)
        });
      } else if (xPosMatch && yPosMatch) {
        // Text position
        const xPos = parseFloat(xPosMatch);
        const yPos = parseFloat(yPosMatch);
        
        if (currentTextBlock) {
          currentTextBlock.positions.push({ x: xPos, y: yPos });
        }
        operations.push({
          operator: 'Td',
          description: 'Move Text Position',
          x: xPos,
          y: yPos
        });
      } else if (tjContentMatch !== undefined) {
        // TJ operator (show text)
        const tjText = extractTJText(`[${tjContentMatch}]`);
        
        if (tjText && currentTextBlock) {
          currentTextBlock.textFragments.push(tjText);
        }
        operations.push({
          operator: 'TJ',
          description: 'Show Text with Positioning',
          rawContent: `[${tjContentMatch}]`,
          extractedText: tjText || ''
        });
      }
      
      lastIndex = operationRegex.lastIndex;
    }
    
    // Process all operations to build a more user-friendly representation
    const result = {
      operations: operations,
      extractedText: operations
        .filter(op => (op.operator === 'TJ' || op.operator === 'Tj') && op.extractedText)
        .map(op => op.extractedText)
        .join(' '),
      textBlocks: operations
        .filter(op => op.operator === 'ET' && op.textBlock)
        .map(op => op.textBlock)
    };
    
    return result;
  } catch (err) {
    console.log(`Error interpreting text operators: ${err.message}`);
    return null;
  }
}

// Function to extract and interpret PDF text operators directly from PDF.js
async function extractTextOperatorsFromPage(page, pageNum, extractionDir, baseFilename, structureOverview) {
  try {
    // Get the operator list WITHOUT clipping to capture out-of-bounds content
    const operatorList = await page.getOperatorList({ disableClipping: true });
    const textOperations = [];
    
    // Get PDF.js operator mappings
    const OPS = {};
    for (const key in pdfjsLib.OPS) {
      OPS[pdfjsLib.OPS[key]] = key;
    }
    
    // Track text state
    let inTextObject = false;
    let currentFont = null;
    let currentFontSize = null;
    let currentTextMatrix = [1, 0, 0, 1, 0, 0]; // Identity matrix
    let currentTextBlock = null;
    let outOfBoundsText = []; // Special array to track potentially hidden text
    
    // Get page dimensions to determine what's "out of bounds"
    const viewport = page.getViewport({ scale: 1.0 });
    const pageWidth = viewport.width;
    const pageHeight = viewport.height;
    
    for (let i = 0; i < operatorList.fnArray.length; i++) {
      const fnId = operatorList.fnArray[i];
      const args = operatorList.argsArray[i];
      const opName = OPS[fnId] || `Unknown(${fnId})`;
      
      // Focus on text-related operators
      if (opName === 'beginText') {
        inTextObject = true;
        currentTextBlock = {
          type: 'TextBlock',
          font: currentFont,
          fontSize: currentFontSize,
          positions: [],
          textFragments: [],
          isOutOfBounds: false // Track if this text block is potentially hidden
        };
        textOperations.push({
          operator: 'BT',
          description: 'Begin Text Object'
        });
      } else if (opName === 'endText') {
        inTextObject = false;
        if (currentTextBlock) {
          textOperations.push({
            operator: 'ET',
            description: 'End Text Object',
            textBlock: { ...currentTextBlock }
          });
        }
        currentTextBlock = null;
      } else if (inTextObject) {
        if (opName === 'setFont' && args.length >= 2) {
          currentFont = args[0];
          currentFontSize = args[1];
          if (currentTextBlock) {
            currentTextBlock.font = currentFont;
            currentTextBlock.fontSize = currentFontSize;
          }
          textOperations.push({
            operator: 'Tf',
            description: 'Set Font and Size',
            font: currentFont,
            fontSize: currentFontSize
          });
        } else if (opName === 'moveText' && args.length >= 2) {
          const x = args[0];
          const y = args[1];
          
          // Enhanced logic to detect unusual coordinates
          // Flag coordinates using a more sophisticated algorithm
          const isOutOfBounds = detectUnusualCoordinates(x, y, viewport.width, viewport.height);
          
          if (currentTextBlock) {
            currentTextBlock.positions.push({ 
              x, 
              y, 
              isOutOfBounds, 
              flagReason: isOutOfBounds ? getCoordinateAnomalyReason(x, y, viewport.width, viewport.height) : null
            });
            
            if (isOutOfBounds) {
              currentTextBlock.isOutOfBounds = true;
              currentTextBlock.anomalyReason = getCoordinateAnomalyReason(x, y, viewport.width, viewport.height);
            }
          }
          
          textOperations.push({
            operator: 'Td',
            description: 'Move Text Position',
            x: x,
            y: y,
            isOutOfBounds: isOutOfBounds,
            flagReason: isOutOfBounds ? getCoordinateAnomalyReason(x, y, viewport.width, viewport.height) : null
          });
        } else if (opName === 'showText' && args.length >= 1) {
          const text = args[0];
          if (currentTextBlock) {
            currentTextBlock.textFragments.push(text);
            
            // If this text block is out of bounds, add to our special array
            if (currentTextBlock.isOutOfBounds) {
              // Extract Unicode text from complex PDF.js text objects
              let extractedText = '';
              if (typeof text === 'string') {
                extractedText = text;
              } else if (typeof text === 'object' && text.unicode) {
                extractedText = text.unicode;
              } else {
                // Handle other types like arrays
                try {
                  extractedText = String(text);
                } catch (e) {
                  extractedText = '[complex text object]';
                }
              }
              
              outOfBoundsText.push({
                text: text,
                extractedText: extractedText,
                x: currentTextBlock.positions.length > 0 ? 
                   currentTextBlock.positions[currentTextBlock.positions.length - 1].x : null,
                y: currentTextBlock.positions.length > 0 ? 
                   currentTextBlock.positions[currentTextBlock.positions.length - 1].y : null,
                font: currentTextBlock.font,
                fontSize: currentTextBlock.fontSize
              });
            }
          }
          
          textOperations.push({
            operator: 'Tj',
            description: 'Show Text',
            text: text
          });
        } else if (opName === 'showSpacedText' && args.length >= 1) {
          const items = args[0];
          let extractedText = '';
          
          // Extract text from the array
          for (const item of items) {
            if (typeof item === 'string') {
              extractedText += item;
              if (currentTextBlock) {
                currentTextBlock.textFragments.push(item);
                
                // If this text block is out of bounds, add to our special array
                if (currentTextBlock.isOutOfBounds) {
                  outOfBoundsText.push({
                    text: item,
                    extractedText: item, // Already a string
                    x: currentTextBlock.positions.length > 0 ? 
                       currentTextBlock.positions[currentTextBlock.positions.length - 1].x : null,
                    y: currentTextBlock.positions.length > 0 ? 
                       currentTextBlock.positions[currentTextBlock.positions.length - 1].y : null,
                    font: currentTextBlock.font,
                    fontSize: currentTextBlock.fontSize
                  });
                }
              }
            } else if (typeof item === 'number') {
              // This is likely a kerning/spacing value, we can skip or add a small space
              if (item < -100) {
                extractedText += ' '; // Add a space for large negative kerning values
              }
            } else if (typeof item === 'object' && item !== null) {
              // Handle complex object with unicode property
              if (item.unicode) {
                extractedText += item.unicode;
                if (currentTextBlock && currentTextBlock.isOutOfBounds) {
                  outOfBoundsText.push({
                    text: item,
                    extractedText: item.unicode,
                    x: currentTextBlock.positions.length > 0 ? 
                       currentTextBlock.positions[currentTextBlock.positions.length - 1].x : null,
                    y: currentTextBlock.positions.length > 0 ? 
                       currentTextBlock.positions[currentTextBlock.positions.length - 1].y : null,
                    font: currentTextBlock.font,
                    fontSize: currentTextBlock.fontSize
                  });
                }
              }
            }
          }
          
          textOperations.push({
            operator: 'TJ',
            description: 'Show Text with Positioning',
            items: items,
            extractedText: extractedText
          });
        }
      }
    }
    
    // Save the extracted text operations
    const result = {
      operations: textOperations,
      extractedText: textOperations
        .filter(op => (op.operator === 'Tj' || op.operator === 'TJ') && op.extractedText)
        .map(op => op.extractedText)
        .join(' '),
      textBlocks: textOperations
        .filter(op => op.operator === 'ET' && op.textBlock)
        .map(op => op.textBlock),
      // Include any detected out-of-bounds text which might contain hidden instructions
      outOfBoundsText: outOfBoundsText
    };
    
    const operatorsFilename = `${baseFilename}_page${pageNum}_text_operators.json`;
    const operatorsPath = path.join(extractionDir, operatorsFilename);
    fs.writeFileSync(operatorsPath, JSON.stringify(result, null, 2));
    structureOverview.extractedFiles.push(operatorsPath);
    
    // If out-of-bounds text was found, save it to a dedicated file for easy access
    if (outOfBoundsText.length > 0) {
      const hiddenTextFilename = `${baseFilename}_page${pageNum}_hidden_text.json`;
      const hiddenTextPath = path.join(extractionDir, hiddenTextFilename);
      
      // Function to extract text from complex text objects or arrays
      const extractTextFromObject = (obj) => {
        if (typeof obj === 'string') return obj;
        if (typeof obj === 'number') return ''; // Skip spacing values
        if (!obj) return '';
        
        // Handle PDF.js text objects
        if (obj.unicode) return obj.unicode;
        
        // If it's an array, process each item
        if (Array.isArray(obj)) {
          return obj.map(extractTextFromObject).join('');
        }
        
        return '';
      };
      
      // Process the text objects to extract readable strings and flag unusual coordinates
      const processedHiddenText = outOfBoundsText.map(item => {
        let processedItem = { ...item };
        
        // If text is an array or complex object, extract the readable parts
        if (item.text) {
          if (Array.isArray(item.text)) {
            processedItem.extractedText = extractTextFromObject(item.text);
          } else if (typeof item.text === 'object') {
            processedItem.extractedText = extractTextFromObject(item.text);
          } else {
            processedItem.extractedText = String(item.text);
          }
        }
        
        return processedItem;
      });
      
      // Group text items by their anomaly reasons to better understand patterns
      const anomalyGroups = {};
      processedHiddenText.forEach(item => {
        if (item.x !== null && item.y !== null) {
          const reason = getCoordinateAnomalyReason(item.x, item.y, viewport.width, viewport.height);
          if (!anomalyGroups[reason]) {
            anomalyGroups[reason] = [];
          }
          anomalyGroups[reason].push(item);
        }
      });
      
      // Put together the full text as a string
      const fullReconstructedText = processedHiddenText
        .map(item => item.extractedText || '')
        .filter(text => text.trim().length > 0)
        .join(' ');
      
      const hiddenTextContent = {
        page: pageNum,
        hiddenText: processedHiddenText,
        reconstructedText: fullReconstructedText,
        // Add a plain text version for easier reading
        plainText: fullReconstructedText.replace(/\s+/g, ' ').trim(),
        // Add a summary of the coordinate anomalies found
        coordinateAnomalies: Object.keys(anomalyGroups).map(reason => ({
          reason,
          count: anomalyGroups[reason].length,
          examples: anomalyGroups[reason].slice(0, 3).map(item => ({
            text: item.extractedText || '',
            position: { x: item.x, y: item.y }
          }))
        }))
      };
      
      fs.writeFileSync(hiddenTextPath, JSON.stringify(hiddenTextContent, null, 2));
      structureOverview.extractedFiles.push(hiddenTextPath);
      
      // Log more detailed info about unusual coordinates
      console.log(`  Found hidden/out-of-bounds text on page ${pageNum}:`);
      console.log(`  Text snippet: "${hiddenTextContent.plainText.substring(0, 100)}${hiddenTextContent.plainText.length > 100 ? '...' : ''}"`);
      console.log(`  Coordinate anomalies detected:`);
      hiddenTextContent.coordinateAnomalies.forEach(anomaly => {
        console.log(`    - ${anomaly.reason} (${anomaly.count} instances)`);
        if (anomaly.examples.length > 0) {
          const example = anomaly.examples[0];
          console.log(`      Example: "${example.text.substring(0, 30)}..." at (${example.position.x.toFixed(2)}, ${example.position.y.toFixed(2)})`);
        }
      });
    }
    
    return result;
  } catch (err) {
    console.log(`Error extracting text operators from page ${pageNum}: ${err.message}`);
    return null;
  }
}

// Detects if coordinates are unusual or outside normal page boundaries
// @param {number} x - X coordinate
// @param {number} y - Y coordinate
// @param {number} pageWidth - Width of page
// @param {number} pageHeight - Height of page
// @returns {boolean} - Whether coordinates are unusual
function detectUnusualCoordinates(x, y, pageWidth, pageHeight) {
  // Coordinates significantly outside page boundaries
  if (x > pageWidth * 1.1) return true;  // More than 10% beyond right edge
  if (x < -pageWidth * 0.1) return true; // More than 10% beyond left edge
  if (y > pageHeight * 1.1) return true; // More than 10% beyond top (in PDF coords, y increases upward)
  if (y < -pageHeight * 0.1) return true; // More than 10% beyond bottom
  
  // Extremely large values that might indicate deliberate hiding
  if (Math.abs(x) > pageWidth * 5) return true;
  if (Math.abs(y) > pageHeight * 5) return true;
  
  // Far corners (might be used to hide text)
  if ((x > pageWidth * 0.9 || x < pageWidth * 0.1) && 
      (y > pageHeight * 0.9 || y < -pageHeight * 0.9)) {
    return true;
  }
  
  return false;
}

// Returns a human-readable explanation for why coordinates are unusual
// @param {number} x - X coordinate
// @param {number} y - Y coordinate
// @param {number} pageWidth - Width of page
// @param {number} pageHeight - Height of page
// @returns {string} - Explanation of why coordinates are unusual
function getCoordinateAnomalyReason(x, y, pageWidth, pageHeight) {
  if (x > pageWidth) {
    return `X coordinate (${x.toFixed(2)}) extends beyond right page edge (${pageWidth.toFixed(2)})`;
  }
  if (x < 0) {
    return `X coordinate (${x.toFixed(2)}) extends beyond left page edge`;
  }
  if (y > pageHeight) {
    return `Y coordinate (${y.toFixed(2)}) extends beyond top page edge (${pageHeight.toFixed(2)})`;
  }
  if (y < -pageHeight) {
    return `Y coordinate (${y.toFixed(2)}) extends below bottom page edge (-${pageHeight.toFixed(2)})`;
  }
  if (Math.abs(x) > pageWidth * 5 || Math.abs(y) > pageHeight * 5) {
    return `Extreme coordinates (${x.toFixed(2)}, ${y.toFixed(2)}) far outside normal range`;
  }
  if ((x > pageWidth * 0.9 || x < pageWidth * 0.1) && 
      (y > pageHeight * 0.9 || y < -pageHeight * 0.9)) {
    return `Corner positioning (${x.toFixed(2)}, ${y.toFixed(2)}) might indicate deliberate hiding`;
  }
  
  return "Unusual coordinates";
}

// Print outline items recursively
// @param {Array} outlineItems - Array of outline items
// @param {number} level - Current nesting level
function printOutlineItems(outlineItems, level = 0) {
  if (!outlineItems || outlineItems.length === 0) return;
  
  const indent = '  '.repeat(level);
  for (const item of outlineItems) {
    console.log(`${indent}- ${item.title}`);
    
    if (item.dest) {
      console.log(`${indent}  Target: ${Array.isArray(item.dest) ? item.dest[0].num + 1 : '[Complex Destination]'}`);
    }
    
    if (item.items && item.items.length > 0) {
      printOutlineItems(item.items, level + 1);
    }
  }
}

// Main execution
(async () => {
  try {
    // Run the main PDF extraction
    console.log("Running main PDF extraction...");
    await extractPDFContent(pdfPath, path.basename(pdfPath, '.pdf') + '_extracted');
    
    // Also run the direct Python-style extraction
    extractPdfStreamsDirectly(pdfPath, path.basename(pdfPath, '.pdf') + '_extracted');
    
  } catch (error) {
    console.error('Fatal error:', error);
    process.exit(1);
  }
})();

// Analyze binary data to detect file signatures
function detectFileType(data) {
  if (!data || data.length < 4) {
    return 'unknown';
  }
  
  // Check common file signatures
  if (data[0] === 0xFF && data[1] === 0xD8 && data[2] === 0xFF) {
    return 'image/jpeg';
  } else if (data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4E && data[3] === 0x47) {
    return 'image/png';
  } else if (data[0] === 0x47 && data[1] === 0x49 && data[2] === 0x46) {
    return 'image/gif';
  } else if (data[0] === 0x25 && data[1] === 0x50 && data[2] === 0x44 && data[3] === 0x46) {
    return 'application/pdf';
  } else if ((data[0] === 0xD0 && data[1] === 0xCF) || (data[0] === 0x50 && data[1] === 0x4B)) {
    return 'application/zip';
  } else if (data.length > 512 && 
             ((data[0] === 0x7F && data[1] === 0x45 && data[2] === 0x4C && data[3] === 0x46) || 
              (data[0] === 0x4D && data[1] === 0x5A))) {
    return 'application/executable';
  }
  
  return 'application/octet-stream';
}
