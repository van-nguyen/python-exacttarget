import uuid
import logging
import os
import sys
import glob

import suds
from suds.client import Client
from suds.wsse import Security, UsernameToken
from urllib2 import URLError

DEFAULT_EVURL = 'https://webservice.exacttarget.com/etframework.wsdl'

class ExactTargetAPI:
    def __init__(self, username, password, schema_url=None, log_path=None):
        self.username = username
        self.password = password
        self.client_id = None

        # it's possible to provide your own modified schema
        if(schema_url):
            self.schema_url = schema_url
        else:
            self.schema_url = DEFAULT_EVURL

        # configure logging for ET errors
        if log_path is not None:
            log_path = os.path.join(log_path, 'ExactTargetAPI.error')
        else:
            log_path = 'ExactTargetAPI.error'

        # create an error logger
        self.logger = logging.getLogger('ExactTargetAPI')
        fh = logging.FileHandler(log_path)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

    def log(self, msg, level=logging.DEBUG):
        if sys.stdout.fileno() is not None and os.isatty(sys.stdout.fileno()):
            print msg
        else:
            self.logger.log(level, msg)

    def init_client(self):
        try:
            # create the SOAP client
            self.client = Client(self.schema_url)
        except URLError as e:
            self.log(e, logging.CRITICAL)
            return None

        # add WS-Security token
        security = Security()
        token = UsernameToken(self.username, self.password)
        security.tokens.append(token)
        self.client.set_options(wsse=security)
        return self.client

    def set_client_id(self, cid):
        self.client_id = self.create('ClientID')
        self.client_id.ID = cid

    def add_to_triggered_send_definition(self, tsd_key, email, subscriberkey,
                                         attribs=None):
        # create a subscriber object
        s = self.client.factory.create('Subscriber')
        s.EmailAddress = email
        s.SubscriberKey = subscriberkey

        # add extra attributes to data extension
        if attribs is not None:
            for k in attribs.keys():
                s.Attributes.append({'Name': k, 'Value': attribs[k]})

        s.Status = 'Active'
        s.EmailTypePreference = 'HTML'
        s.PrimarySMSPublicationStatus = 'OptedIn'

        tsd = self.client.factory.create('TriggeredSendDefinition')
        tsd.SourceAddressType = 'DefaultPrivateIPAddress'
        tsd.DomainType = 'DefaultDomain'
        tsd.HeaderSalutationSource = 'None'
        tsd.FooterSalutationSource = 'None'
        tsd.TriggeredSendType = 'Continuous'    # not sure about this
        tsd.TriggeredSendStatus = 'Active'
        tsd.CustomerKey = tsd_key

        ts = self.client.factory.create('TriggeredSend')
        ts.TriggeredSendDefinition = tsd
        ts.Subscribers = [s]

        co = self.client.factory.create('CreateOptions')
        co.RequestType = 'Synchronous'
        co.QueuePriority = 'Medium'
        so = self.client.factory.create('SaveOption')
        so.PropertyName = '*'
        so.SaveAction = 'UpdateAdd'
        co.SaveOptions = [so]

        opts = [ts]

        try:
            resp = self.client.service.Create(co, opts)
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

        return resp.RequestID

    def _create_api_property(self, name, value):
        p = self.client.factory.create('APIProperty')
        p.Name = name
        p.Value = value
        return p

    def add_to_data_extension(self, de_key, rows):
        opts = []
        
        # convert props to WSDL format
        for props in rows:
            apiprops = []
            for k in props.keys():
                apiprops.append(self._create_api_property(k, props[k]))
    
            # create DE and map in our properties array
            deo = self.client.factory.create('DataExtensionObject')
            innerprops = []
            for p in apiprops:
                innerprops.append(p)
                deo.Properties = [{'Property': innerprops}]
                deo.CustomerKey = de_key
            
            opts.append(deo)
            
        # createoptions for insertion
        co = self.client.factory.create('CreateOptions')
        co.RequestType = 'Asynchronous'
        co.QueuePriority = 'Medium'
        so = self.client.factory.create('SaveOption')
        so.PropertyName = '*'
        so.SaveAction = 'UpdateAdd'
        co.SaveOptions = [so]

        print self.client.service.Create(co, opts)

    def get_subscriber(self, key):
        # retrieve a subscriber
        rr = self.client.factory.create('RetrieveRequest')
        rr.ObjectType = 'Subscriber'
        rr.Properties = ['ID', 'EmailAddress', 'SubscriberKey',
                         'UnsubscribedDate', 'Status', 'EmailTypePreference']
        rr.Options = None

        sfp = self.client.factory.create('SimpleFilterPart')
        sfp.Property = 'SubscriberKey'
        sfp.SimpleOperator = 'equals'
        sfp.Value = key
        rr.Filter = sfp

        try:
            resp = self.client.service.Retrieve(rr)
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

        try:
            return resp.Results[0]
        except AttributeError:
            pass

        return None
    
    def create(self, objtype, key=None):
        obj = self.client.factory.create(objtype)
        
        for p in obj.__keylist__:
            obj[p] = None
        
        if key is not None:
            obj.CustomerKey = key
        
        return obj
    
    def _deo_to_list(self, resp):
        results = []
        
        if 'Results' not in resp:
            return None
        
        for r in resp.Results:
            row = {}
            
            for p in r.Properties.Property:
                row[p.Name] = p.Value
                
            results.append(row)
            
        return results
    
    def get_data_extension(self, de_key, cols, start_date=None, start_date_field=None, more_data=True):
        rr = self.client.factory.create('RetrieveRequest')
        rr.ObjectType = 'DataExtensionObject[' + de_key + ']'
        rr.Properties = cols
        rr.Options = None
        
        if start_date is not None and start_date_field is not None:
            sfp = self.client.factory.create('SimpleFilterPart')
            sfp.Property = start_date_field
            sfp.SimpleOperator = 'greaterThanOrEqual'
            sfp.Value = start_date
            rr.Filter = sfp
        
        while True:
            try:
                resp = self.client.service.Retrieve(rr)
                yield self._deo_to_list(resp)
            except suds.WebFault:
                continue
            break

        if more_data:
            while resp.OverallStatus == 'MoreDataAvailable':
                rr = self.client.factory.create('RetrieveRequest')
                rr.ContinueRequest = resp.RequestID
                
                while True:
                    try:
                        resp = self.client.service.Retrieve(rr)
                        yield self._deo_to_list(resp)
                    except suds.WebFault:
                        continue
                    break
                
    def get_object(self, objtype, props):
        rr = self.create('RetrieveRequest')
        rr.ObjectType = objtype
        rr.Properties = props
        rr.ClientIDs  = [self.client_id]

        try:
            resp = self.client.service.Retrieve(rr)
        except suds.WebFault as e:
            raise SoapError(str(e))
        
        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)
        
        return resp.Results
    
    def strip_object(self, obj):
        id_list = ['ObjectID', 'ID', 'CustomerKey']
        
        for p in obj.__keylist__:
                if p not in id_list:
                    obj[p] = None
                    
        return obj
    
    def delete_objects(self, objs):
        for o in objs:
            self.strip_object(o)

        try:
            resp = self.client.service.Delete(None, objs)
        except suds.WebFault as e:
            raise SoapError(str(e))
        
        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)
        
        return True
    
    def update_object(self, obj):
        try:
            resp = self.client.service.Update(None, obj)
        except suds.WebFault as e:
            raise SoapError(str(e))
        
        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)
        
        return True
    
    def create_email(self, name, subject, is_html, body, folder=None):
        email = self.create('Email')
        email.Name = name
        email.Subject = subject
        email.Folder = folder
        email.CharacterSet = 'UTF-8'
        
        if is_html:
            email.EmailType = 'HTML'
            email.HTMLBody = body
            email.IsHTMLPaste = True
        else:
            email.EmailType = 'Text Only'
            email.TextBody = body
            
        try:
            resp = self.client.service.Create(None, [email])
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

        ret_obj = resp.Results[0].Object
        ret_obj.ID = resp.Results[0].NewID
        return ret_obj
    
    def create_tsd(self, name, key, email, de=None, et_list=None, is_transactional=False, add_subscribers=True):
        tsd = self.create('TriggeredSendDefinition')
        tsd.Name = name
        tsd.CustomerKey = key
        tsd.Email = self.strip_object(email)
        tsd.SendClassification = self.create('SendClassification')
        tsd.SendClassification.CustomerKey = 'Default Commercial'
        
        if is_transactional:
            tsd.SendClassification.CustomerKey = 'Default Transactional'
        
        tsd.IsMultipart = True
        
        if et_list:
            tsd.List = self.strip_object(et_list)
            tsd.AutoAddSubscribers = add_subscribers
            
        tsd.SendSourceDataExtension = self.strip_object(de)
        
        try:
            resp = self.client.service.Create(None, [tsd])
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)
        
        return resp.Results[0].Object
    
    def create_data_extension_field(self, name, field_type, is_primary=False, is_nillable=False, length=None, default=None):
        field = self.create('DataExtensionField')
        field.Name = name
        field.FieldType = field_type
        field.IsPrimaryKey = is_primary
        field.IsRequired = not is_nillable
        field.IsNillable = is_nillable
        field.MaxLength = length
        field.DefaultValue = default
        
        return field
    
    def create_data_extension(self, name, key, de_fields, sender_field=None, description=None, folder=None, template=None):
        de = self.create('DataExtension')
        de.Name = name
        de.Description = description
        de.CustomerKey = key
        de.IsSendable = False
        
        # TriggeredSendDataExtension
        if template is not None:
            for o in self.get_object('DataExtensionTemplate', ['Name', 'ObjectID']):
                if o.Name == template:
                    de.Template = o
                    sender_field = 'SubscriberKey'
                    break
        
        de.CategoryID = folder
        
        if sender_field is not None:
            de.IsSendable = True
            de.SendableDataExtensionField = sender_field
            de.SendableSubscriberField = self.create('Attribute')
            de.SendableSubscriberField.Name = "Subscriber Key"
            de.SendableSubscriberField.Value = ""
        
        # arrays of self.create_data_extension_field
        de.Fields = {'Field': de_fields}

        try:
            resp = self.client.service.Create(None, [de])
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

        return resp.Results[0].Object
        
    def create_subscriber(self, email, firstname, lastname, listname=None):
        # create subscriber object
        s = self.client.factory.create('Subscriber')
        s.EmailAddress = email
        s.SubscriberKey = uuid.uuid1()
        s.Status = 'Active'
        s.EmailTypePreference = 'HTML'
        s.PrimarySMSPublicationStatus = 'OptedIn'
        s.Attributes = [
            {'Name':'First Name', 'Value':firstname},
            {'Name':'Last Name', 'Value':lastname}
        ]

        # add the subscriber to a list if supplied
        if listname is not None:
            l = self.get_subscriber_list(listname)

            if l is not None:
                sl = self.client.factory.create('SubscriberList')
                sl.ID = l.ID
                sl.Status = 'Active'
                s.Lists = [sl]

        co = self.client.factory.create('CreateOptions')
        co.RequestType = 'Synchronous'
        co.QueuePriority = 'Medium'
        so = self.client.factory.create('SaveOption')
        so.PropertyName = '*'
        so.SaveAction = 'UpdateAdd'
        co.SaveOptions = [so]

        opts = [s]

        try:
            resp = self.client.service.Create(co, opts)
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

        return s

    def get_subscriber_list(self, listname, create_if_not_exists=False):
        # retrieve a subscriber list
        rr = self.client.factory.create('RetrieveRequest')
        rr.ObjectType = 'List'
        rr.Properties = ['ID', 'ListName', 'Description', 'Type',
                         'ListClassification']
        rr.Options = None

        sfp = self.client.factory.create('SimpleFilterPart')
        sfp.Property = 'ListName'
        sfp.SimpleOperator = 'equals'
        sfp.Value = listname
        rr.Filter = sfp

        try:
            resp = self.client.service.Retrieve(rr)
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

        try:
            return resp.Results[0]
        except AttributeError:
            pass

        # create the subscriber list
        if create_if_not_exists == True:
            return self.create_subscriber_list(listname)
        else:
            return None

    def add_subscribers_to_list(self, subs, async=True):
        sublist = self.create('SubscriberList')
        sublist.Action = 'create'
        
        objs = []
        
        for subscribers in subs:
            sublist.ID = subscribers[0]
            
            for email in subscribers[1]:
                sub = self.create('Subscriber')
                sub.SubscriberKey = email
                sub.EmailAddress = email
                sub.Lists = [sublist]
                objs.append(sub)
        
        uo = self.create('UpdateOptions')
        if async:
            uo.RequestType = 'Asynchronous'
        
        for obj in chunks(objs, 400):
            try:
                resp = self.client.service.Create(None, obj)
            except suds.WebFault as e:
                raise SoapError(str(e))
            
            if resp.OverallStatus != 'OK':
                self.log(resp, logging.ERROR)
                raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

    def create_subscriber_lists(self, lists, folder=0):
        objs = []
        
        for li in lists:
            l = self.create('List')
            
            if folder > 0:
                l.Category = folder
            
            l.CustomerKey = li['key']
            l.ListName = li['name']
            l.Description = li['description']
            
            objs.append(l)

        try:
            resp = self.client.service.Create(None, objs)
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)
        else:
            list_obs = {}
            for r in resp.Results:
                list_obs[r.Object.CustomerKey] = r.NewID
            
            return list_obs

    def get_email_receivers(self, jobid):
        # retrieve all users who received this email
        rr = self.client.factory.create('RetrieveRequest')
        rr.ObjectType = 'SentEvent'
        rr.Properties = ['SendID', 'EventDate', 'SubscriberKey']
        rr.Options = None

        sfp = self.client.factory.create('SimpleFilterPart')
        sfp.Property = 'SendID'
        sfp.SimpleOperator = 'equals'
        sfp.Value = jobid
        rr.Filter = sfp

        try:
            resp = self.client.service.Retrieve(rr)
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

        try:
            return resp.Results[0]
        except AttributeError:
            pass

    def get_email_stats(self, jobid):
        # retrieve stats on a single email send
        rr = self.client.factory.create('RetrieveRequest')
        rr.ObjectType = 'Send'
        rr.Properties = ['SentDate', 'UniqueOpens', 'NumberSent', 'NumberDelivered', 'HardBounces', 'SoftBounces']
        rr.Options = None

        sfp = self.client.factory.create('SimpleFilterPart')
        sfp.Property = 'ID'
        sfp.SimpleOperator = 'equals'
        sfp.Value = jobid
        rr.Filter = sfp

        try:
            resp = self.client.service.Retrieve(rr)
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

        try:
            return resp.Results[0]
        except AttributeError:
            pass
    
    def create_filter(self, prop, operator, value):
        sfp = self.create('SimpleFilterPart')
        sfp.Property = prop
        sfp.SimpleOperator = operator
        sfp.Value = value
        return sfp
    
    def create_filter_definition(self, name, filters, key=None, description=None, operator='AND'):
        fd = self.create('FilterDefinition', key)
        fd.Name = name
        fd.Description = description
        filter_len = len(filters)
        
        if filter_len is 1:
            fd.DataFilter = self.create_filter(*filters[0])
        else:
            cfp = self.create('SimpleFilterPart')
            cfp.LeftOperand = self.create_filter(*filters[0])
            cfp.LogicalOperator = operator
            cfp.RightOperand = self.create_filter(*filters[1])
            
            if filter_len > 2:
                cfp.AdditionalOperands = []
                for f in filters[2:]:
                    cfp.AdditionalOperands.append(self.create_filter(*f))
                    
            fd.DataFilter = cfp
            
        self.client.service.Create(None, fd)

    def start_tsd(self, tsd):
        tsd.TriggeredSendStatus = 'Active'
        self.update_object(tsd)
    
    def stop_tsd(self, tsd):
        tsd.TriggeredSendStatus = 'Inactive'
        self.update_object(tsd)

    def run_import(self, key):
        im = self.create('ImportDefinition')
        im.CustomerKey = key
        
        objs = {'Definition': [im,]}
        
        try:
            resp = self.client.service.Perform(self.create('PerformOptions'), 'start', objs)
        except suds.WebFault as e:
            raise SoapError(str(e))

        if resp.OverallStatus != 'OK':
            self.log(resp, logging.ERROR)
            raise ExactTargetError(resp.RequestID, resp.Results[0].StatusMessage)

class ExactTargetError(Exception):
    def __init__(self, request_id, message):
        Exception.__init__(self, message)
        self.request_id = request_id

    def __unicode__(self):
        return "Request %s failed with message '%s'" % (self.request_id, self.message)

    def __str__(self):
        return str(self.__unicode__())


class SoapError(Exception):
    pass

# http://stackoverflow.com/a/1751478/271768
def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]
