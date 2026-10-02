from .common import *
from .crypto import *
def audit(d):
    fields(d,['envelope','trusted_keys','expected_payload_type','threshold'])
    e=obj(d['envelope']);fields(e,['payloadType','payload','signatures'])
    t=string(e['payloadType'],1024);need(t==string(d['expected_payload_type'],1024),"unexpected payload type")
    body=b64(e['payload']);siglist=seq(e['signatures'],128);need(siglist,"no signatures")
    keys=[pubkey(v) for v in seq(d['trusted_keys'],128)];need(keys,"no trusted keys")
    fps=[fingerprint(k) for k in keys];need(len(set(fps))==len(fps),"duplicate trusted public key")
    need(all(isinstance(k,ed25519.Ed25519PublicKey) for k in keys),"only Ed25519 keys supported")
    threshold=integer(d['threshold'],1,len(keys));encoded=t.encode('utf-8')
    pae=b'DSSEv1 '+str(len(encoded)).encode()+b' '+encoded+b' '+str(len(body)).encode()+b' '+body
    accepted=set();seen=set()
    for s in siglist:
        fields(s,['sig'],['keyid']);raw=b64(s['sig'],limit=64);need(len(raw)==64 and raw not in seen,"invalid or duplicate signature");seen.add(raw)
        if 'keyid' in s:string(s['keyid'],1024)
        matched=False
        for k,fp in zip(keys,fps):
            try:valid_public_key(k);valid_ed_signature(raw);k.verify(raw,pae);accepted.add(fp);matched=True
            except InvalidSignature:pass
        need(matched,"signature not valid for any pinned key")
    need(len(accepted)>=threshold,"signature threshold unmet")
    return report(verified=True,payload_type=t,payload_sha256=hashlib.sha256(body).hexdigest(),accepted_key_count=len(accepted),threshold=threshold)
