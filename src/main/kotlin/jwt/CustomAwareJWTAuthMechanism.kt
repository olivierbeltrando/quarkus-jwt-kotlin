package jwt

import io.quarkus.security.identity.IdentityProviderManager
import io.quarkus.security.identity.SecurityIdentity
import io.quarkus.security.identity.request.AuthenticationRequest
import io.quarkus.smallrye.jwt.runtime.auth.JWTAuthMechanism
import io.quarkus.vertx.http.runtime.security.ChallengeData
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport
import io.smallrye.mutiny.Uni
import io.vertx.ext.web.RoutingContext
import jakarta.annotation.Priority
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Alternative
import jakarta.inject.Inject
import org.slf4j.Logger
import org.slf4j.LoggerFactory


@Alternative
@Priority(1)
@ApplicationScoped
class CustomAwareJWTAuthMechanism : HttpAuthenticationMechanism {

    @Inject
    var delegate: JWTAuthMechanism? = null

    override fun authenticate(context: RoutingContext?, identityProviderManager: IdentityProviderManager?): Uni<SecurityIdentity?>? {
        // do some custom action and delegate
        return delegate?.authenticate(context, identityProviderManager)?.map { securityIdentity: SecurityIdentity? ->
            securityIdentity ?: null
        }
//        return delegate!!.authenticate(context, identityProviderManager)
    }

    override fun getChallenge(context: RoutingContext?): Uni<ChallengeData?>? {
        return delegate!!.getChallenge(context)
    }

    override fun getCredentialTypes(): Set<Class<out AuthenticationRequest?>?>? {
        return delegate!!.credentialTypes
    }

//    override fun getCredentialTransport(): HttpCredentialTransport? {
//        return delegate!!.credentialTransport
//    }

}