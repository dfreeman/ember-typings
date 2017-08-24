import UnauthenticatedRouteMixin from 'ember-simple-auth/mixins/unauthenticated-route-mixin';
import Route from '@ember/routing/route';

class MyRoute extends Route.extend(UnauthenticatedRouteMixin) {
    model() {
        console.log(this.routeIfAlreadyAuthenticated);
    }
}
