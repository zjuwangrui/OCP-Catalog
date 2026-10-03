import {
  appendRelayHop,
  type AppendRelayHopParams,
  type AttributionToken,
} from './attribution';
import {
  verifyAttributionToken,
  type AttributionKeyResolver,
  type AttributionVerdict,
} from './verify';

export interface VerifyAndAppendRelayHopParams extends Omit<AppendRelayHopParams, 'token'> {
  token: AttributionToken;
  resolveKey: AttributionKeyResolver;
  at?: Date;
}

/** Verifies every upstream hop before this relay adds its own signed hop. */
export async function verifyAndAppendRelayHop(
  params: VerifyAndAppendRelayHopParams,
): Promise<{ token: AttributionToken; upstream: AttributionVerdict }> {
  const { token, resolveKey, at, ...append } = params;
  const upstream = await verifyAttributionToken({ token, resolveKey, at });
  if (!upstream.ok) throw upstream.error;
  return { token: appendRelayHop({ ...append, token }), upstream };
}
