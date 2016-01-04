/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.server.global;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser;

/**
 * An initial handler for &quot;hostkeys-prove-00@openssh.com&quot; request
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH protocol - section 2.5</a>
 */
public class OpenSshHostKeysHandler extends AbstractOpenSshHostKeysHandler implements SignatureFactoriesManager {
    public static final String REQUEST = "hostkeys-prove-00@openssh.com";
    public static final OpenSshHostKeysHandler INSTANCE = new OpenSshHostKeysHandler() {
        @Override
        public List<NamedFactory<Signature>> getSignatureFactories() {
            return null;
        }

        @Override
        public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
            if (!GenericUtils.isEmpty(factories)) {
                throw new UnsupportedOperationException("Not allowed to change default instance signature factories");
            }
        }
    };

    private List<NamedFactory<Signature>> factories;

    public OpenSshHostKeysHandler() {
        super(REQUEST);
    }

    public OpenSshHostKeysHandler(BufferPublicKeyParser<? extends PublicKey> parser) {
        super(REQUEST, parser);
    }

    @Override
    public List<NamedFactory<Signature>> getSignatureFactories() {
        return factories;
    }

    @Override
    public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
        this.factories = factories;
    }

    @Override
    protected Result handleHostKeys(Session session, Collection<? extends PublicKey> keys, boolean wantReply, Buffer buffer) throws Exception {
        // according to the specification there MUST be reply required by the server
        ValidateUtils.checkTrue(wantReply, "No reply required for host keys of %s", session);
        Collection<? extends NamedFactory<Signature>> factories =
                ValidateUtils.checkNotNullAndNotEmpty(
                        SignatureFactoriesManager.Utils.resolveSignatureFactories(this, session),
                        "No signature factories available for host keys of session=%s",
                        session);
        if (log.isDebugEnabled()) {
            log.debug("handleHostKeys({})[want-reply={}] received {} keys - factories={}",
                      session, wantReply, GenericUtils.size(keys), NamedResource.Utils.getNames(factories));
        }

        // generate the required signatures
        buffer = session.prepareBuffer(SshConstants.SSH_MSG_REQUEST_SUCCESS, BufferUtils.clear(buffer));

        Buffer buf = new ByteArrayBuffer();
        byte[] sessionId = session.getSessionId();
        KeyPairProvider kpp = ValidateUtils.checkNotNull(session.getKeyPairProvider(), "No server keys provider");
        for (PublicKey k : keys) {
            String keyType = KeyUtils.getKeyType(k);
            Signature verifier = ValidateUtils.checkNotNull(
                    NamedFactory.Utils.create(factories, keyType),
                    "No signer could be located for key type=%s",
                    keyType);

            KeyPair kp = ValidateUtils.checkNotNull(kpp.loadKey(keyType), "No key of type=%s available", keyType);
            verifier.initSigner(kp.getPrivate());

            buf.clear();
            buf.putString(REQUEST);
            buf.putBytes(sessionId);
            buf.putPublicKey(k);

            byte[] data = buf.getCompactData();
            verifier.update(data);

            byte[] signature = verifier.sign();
            buffer.putBytes(signature);
        }

        session.writePacket(buffer);
        return Result.Replied;
    }
}
