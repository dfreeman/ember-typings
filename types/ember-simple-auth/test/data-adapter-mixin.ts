import EmberObject from '@ember/object';
import DataAdapterMixin from 'ember-simple-auth/mixins/data-adapter-mixin';

class ApplicationAdapter extends EmberObject.extend(DataAdapterMixin) {
    init() {
        super.init();

        let authorizer = this.authorizer || 'default-authorizer';
        this.session.authorize(authorizer, (name, content) => {
            console.log(name, content);
        });
    }
}
