function return_text (r, code, msg) {
  r.status = code
  r.headersOut['Content-Type'] = 'text/plain; charset=utf-8';
  r.headersOut['Content-Length'] = msg.length;
  r.sendHeader()
  r.send(msg)
  r.finish()
}

function flag_getinfo_403 (r) {
  return_text(r, 403, 'ERROR_ACCESS_DENIED')
}

function flag_getinfo_404 (r) {
  return_text(r, 404, 'ERROR_NOT_FOUND')
}

function flag_getinfo_429 (r) {
  return_text(r, 429, 'ERROR_RATELIMIT')
}

function flag_submit_403 (r) {
  return_text(r, 403, 'ERROR_ACCESS_DENIED')
}

function flag_submit_413 (r) {
  return_text(r, 413, 'ERROR_FLAG_INVALID')
}

function flag_submit_429 (r) {
  return_text(r, 429, 'ERROR_RATELIMIT')
}

function service_getstatus_403 (r) {
  return_text(r, 403, 'ERROR_ACCESS_DENIED')
}

function service_getstatus_404 (r) {
  return_text(r, 404, 'ERROR_NOT_FOUND')
}

function service_getstatus_429 (r) {
  return_text(r, 429, 'ERROR_RATELIMIT')
}
