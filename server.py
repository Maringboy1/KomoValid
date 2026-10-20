"""
Flask Server for KomoValid / KomoSign Valid.
Serves the web application and provides API endpoints for digital signature validation,
verified display copy baking, and PDF digital stamping.
"""

import os
import io
import zipfile
from flask import Flask, request, jsonify, send_file, send_from_directory
from validator import PDFSignatureValidator
from trust_store import CCA_ROOTS, LICENSED_CAS, DOCUMENT_TYPES

app = Flask(__name__, static_folder=".")
validator = PDFSignatureValidator()

# Counter for documents validated
validated_counter = 125520


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    return response


@app.route("/")
def index():
    return send_file("index.html")


@app.route("/<path:path>")
def static_files(path):
    if os.path.exists(path):
        return send_file(path)
    img_candidate = os.path.join("img", path)
    if os.path.exists(img_candidate):
        return send_file(img_candidate)
    return send_file("index.html")


@app.route("/api/validate", methods=["POST"])
def api_validate():
    global validated_counter
    if "file" not in request.files:
        print("[KomoValid ERROR] No file in POST request", flush=True)
        return jsonify({
            "verdict": "error",
            "error_code": "NO_FILE",
            "message": "No file uploaded."
        }), 400

    file = request.files["file"]
    password = request.form.get("password") or None
    pdf_bytes = file.read()

    if not pdf_bytes:
        print("[KomoValid ERROR] Uploaded file is empty", flush=True)
        return jsonify({
            "verdict": "error",
            "error_code": "EMPTY_FILE",
            "message": "Uploaded file is empty."
        }), 400

    print(f"[KomoValid] Received '{file.filename}' ({len(pdf_bytes)} bytes) - scanning for signature...", flush=True)
    result = validator.validate_pdf(pdf_bytes, password=password)
    print(f"[KomoValid] Verdict: {result.get('verdict')} | Previews generated: {len(result.get('preview_pages', []))}", flush=True)
    
    if result.get("verdict") == "valid":
        validated_counter += 1

    return jsonify(result)


@app.route("/api/bake", methods=["POST"])
def api_bake():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    password = request.form.get("password") or None
    sig_index = int(request.form.get("sig_index") or 0)
    pdf_bytes = file.read()

    print(f"[KomoValid] Baking verified display copy for '{file.filename}'...", flush=True)
    try:
        baked_bytes = validator.bake_verified_pdf(pdf_bytes, password=password, sig_index=sig_index)
        orig_name = file.filename or "document.pdf"
        base, ext = os.path.splitext(orig_name)
        out_name = f"{base}_verified_display_copy.pdf"
        print(f"[KomoValid] Successfully baked verified copy ({len(baked_bytes)} bytes). Sending to user.", flush=True)

        return send_file(
            io.BytesIO(baked_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=out_name
        )
    except Exception as e:
        print(f"[KomoValid ERROR] Baking failed: {e}", flush=True)
        return jsonify({"error": f"Failed to bake verified copy: {str(e)}"}), 500


@app.route("/api/batch-bake", methods=["POST"])
def api_batch_bake():
    uploaded_files = request.files.getlist("files")
    if not uploaded_files:
        return jsonify({"error": "No files uploaded for batch baking"}), 400

    print(f"[KomoValid Batch] Baking {len(uploaded_files)} files into ZIP archive...", flush=True)
    zip_buffer = io.BytesIO()

    try:
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in uploaded_files:
                pdf_bytes = file.read()
                if not pdf_bytes:
                    continue
                orig_name = file.filename or "document.pdf"
                base, ext = os.path.splitext(orig_name)
                out_name = f"{base}_verified_display_copy.pdf"
                try:
                    baked_bytes = validator.bake_verified_pdf(pdf_bytes)
                    zf.writestr(out_name, baked_bytes)
                except Exception as file_err:
                    print(f"[KomoValid Batch Warning] Failed baking {orig_name}: {file_err}", flush=True)
                    # If baking failed (e.g. no signature), write original or fallback
                    zf.writestr(orig_name, pdf_bytes)

        zip_buffer.seek(0)
        return send_file(
            zip_buffer,
            mimetype="application/zip",
            as_attachment=True,
            download_name="KomoValid_Verified_Documents.zip"
        )
    except Exception as e:
        print(f"[KomoValid Batch ERROR] Batch ZIP generation failed: {e}", flush=True)
        return jsonify({"error": f"Failed to create batch ZIP: {str(e)}"}), 500


@app.route("/api/sign", methods=["POST"])
def api_sign():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    signer_name = request.form.get("signer_name") or "Authorized Signatory"
    reason = request.form.get("reason") or "Verified Digital Signature"
    location = request.form.get("location") or "Manipur, India"
    page_num = int(request.form.get("page_num") or 1)
    pdf_bytes = file.read()

    try:
        signed_bytes = validator.stamp_custom_signature(
            pdf_bytes,
            signer_name=signer_name,
            reason=reason,
            location=location,
            page_num=page_num
        )
        orig_name = file.filename or "document.pdf"
        base, ext = os.path.splitext(orig_name)
        out_name = f"{base}_digitally_signed.pdf"

        return send_file(
            io.BytesIO(signed_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=out_name
        )
    except Exception as e:
        return jsonify({"error": f"Failed to sign document: {str(e)}"}), 500


@app.route("/api/trust-store", methods=["GET"])
def api_trust_store():
    return jsonify({
        "roots": CCA_ROOTS,
        "authorities": LICENSED_CAS,
        "total_roots": len(CCA_ROOTS),
        "total_authorities": len(LICENSED_CAS)
    })


@app.route("/api/stats", methods=["GET"])
def api_stats():
    return jsonify({
        "total_validated": validated_counter,
        "current_roots": "CCA India 2022 · CCA India 2022 SPL",
        "licensed_authorities": 27,
        "certificates_in_store": 161
    })





if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting KomoValid server on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)

