#!groovy

node 
{
    def lambdaZipVersion = 4
    // AWS 
    def awsRegion="eu-central-1"
    
	// Print identity the AWS commands are running with 
    awsIdentity()

	//Tags
	def owner = 'Owner=CO-IAM'
	def name = 'Name=CO-IAM-' + awsEnvironment
	def orgunit = 'OrgUnit=CloudOps'
	def user = 'user:Environment=' + awsEnvironment
	
	//Print parameter
    echo ('awsEnvironment: ' + awsEnvironment)
    echo ('repo: ' + repo)

	def awsUser='AWS-'+ awsEnvironment.toUpperCase() //AWS IAM-User credentials
	echo ('credentialId: ' + credentialId)
	echo ('AwsUser(Key): ' + awsUser)
		
	/////Alerts//////
	
	// Stack settings
    def stackAlertServiceLimits='AZD-ALERTS-LIMITS-SERVICELIMITS-' + awsEnvironment.toUpperCase()
	def stackAlerts='AZD-ALERTS-' + awsEnvironment.toUpperCase()
	

	// CloudFormation alert templates
    def cfnServiceLimits='Alerts/Limits/ServiceLimits/'+'ServiceLimits'+'.template'
	def cfnAlerting='Alerts/Alerting/Alerting'+'.template'

	//Ouputs
    
	def cfnOutputsAlerts = null
	//HipChat variables
	def msg = ''
	def commitChangeset = ''
	def commitMsg = ''
	def commit1 = ''
	def counter = 0
	

	
	try
	{
	
		stage('Checkout from git') 
		{
			git branch: 'master', credentialsId: credentialId, url: repo	 
			 
			commitChangeset = sh(returnStdout: true, script: 'git diff-tree --no-commit-id --name-status -r HEAD').split()
		
			for( String values : commitChangeset )
			{
				if ( counter % 2 == 0 ) 
				{
					commitMsg = commitMsg  +"<br>["+ (values)+ "]";
				} 
				else 
				{
					commitMsg = commitMsg  +"   "+ (values);
				}
				counter = counter +1
			}
		}

			stage('Uploading Zips')
			{
				withAWS(region:awsRegion, credentials:awsUser) 
					{	
						s3Upload(bucket:'aws-alerting', file:'Alerts/Limits/ServiceLimits/'+'ServiceLimitMonitoring'+'.zip', path:'ServiceLimitMonitoring'+lambdaZipVersion+'.zip', acl:'PublicReadWrite' )
					}
				withAWS(region:awsRegion, credentials:awsUser) 
					{	
						s3Upload(bucket:'aws-alerting', file:'Alerts/Alerting/Alerting'+'.zip', path:'Alerting'+lambdaZipVersion+'.zip', acl:'PublicReadWrite' )
					}
				
			}
			
			stage('Update Alerts') 
			{
			
				//ServiceLimitMonitoring
				withAWS(region:awsRegion, credentials:awsUser) 
					{
						cfnOutputsAlerts = cfnUpdate(stack:stackAlertServiceLimits, file:cfnServiceLimits, params:[], keepParams:[], tags:[owner,name,orgunit, user])
					}
				//Alerting
				withAWS(region:awsRegion, credentials:awsUser) 
					{
						cfnOutputsAlerts = cfnUpdate(stack:stackAlerts, file:cfnAlerting, params:[], keepParams:[], tags:[owner,name,orgunit, user])
					}
			} 

			stage('SendNotifications') 
			{
				hipchatSend color: 'GREEN', 
				token:'xS5niEACKma31yTIOzpHvuDUH9dCBmCZAUMftePi', 
				failOnError: true, 
				message: 'There have been changes for alerting in the ' + awsEnvironment.toUpperCase() + '-Account. Following files have been changed: ' + commitMsg  + "<br> More Information regarding AWS-Alarming can be found in our <a href='https://ind-wiki.allianz.de.awin/pages/viewpage.action?pageId=854430267'>Wiki</a>" , 
				notify: true,  
				room: 'CloudOps - Jenkins deployments', 
				server: 'hipchat.azd.io',
				textFormat: true, 
				v2enabled: true

			}
	
	}
		catch(e){
		echo(e.toString()) 
        hipchatSend color: 'RED', 
		token:'xS5niEACKma31yTIOzpHvuDUH9dCBmCZAUMftePi', 
		failOnError: true, 
		message: 'The jenkinsjob for alerting in the :' + awsEnvironment.toUpperCase() + '-environment did not run as expected. Errormessage: ' + e.toString(), 
		notify: true,  
		room: 'CloudOps - Jenkins deployments', 
		server: 'hipchat.azd.io',
		v2enabled: true
                }

	
	
}