# sanitize-pdf

Use node18, run with 

```bash
npm install
node tools/pdf-extractor.js <pdf-file>
```

## Output

The script will create a directory named after the PDF file (e.g., `<pdf-file>_extracted`) and save all extracted content in it. The extracted content includes:

- Text content
- Encryption information
- Document metadata
- Document outline
- Document attachments
- Document streams
- Extraction summary
- Out-of-bounds text (labeled as coordinateAnomalies)
