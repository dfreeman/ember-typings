import AuthenticatedRouteMixin from 'ember-simple-auth/mixins/authenticated-route-mixin';
import Route from '@ember/routing/route';

class MyRoute extends Route.extend(AuthenticatedRouteMixin) {
    model() {
        return this.session.authenticate('custom-authenticator');
    }
}
