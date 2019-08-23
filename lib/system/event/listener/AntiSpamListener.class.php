<?php
/**
 * @package     zero-24.antispam.extended
 * @copyright   Copyright (C) 2005 - 2019 Tobias Zulauf (https://forum.joomla.de) Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */
namespace wbb\system\event\listener;

use wcf\system\event\listener\IParameterizedEventListener;
use wcf\system\WCF;

/**
 * Anti Spam Extended Listener
 *
 * @since  1.0.0
 */
class AntiSpamListener implements IParameterizedEventListener
{
	/**
	 * Whitelisted chars that should be excluded from the checks
	 *
	 * @var     array
	 * @since   1.0.0
	 */
	private $whitelistedChars = ['ß'];

	/**
	 * The Event Listener execute method that handles the checks
	 *
	 * @param   object   $eventObj    The event object
	 * @param   string   $className   The classname
	 * @param   string   $eventName   The event name
	 * @param   array    $parameters  The event parameters array
	 *
	 * @return  void
	 *
	 * @see     \wcf\system\event\listener\IParameterizedEventListener::execute()
	 * @since   1.0.0
	 */
	public function execute($eventObj, $className, $eventName, array &$parameters)
	{
		// The restrictions should only apply to users with less than 5 posts
		if (WCF::getUser()->wbbPosts >= 5)
		{
			return;
		}

		$actionName = $eventObj->getActionName();
		$parameters = $eventObj->getParameters();

		switch ($actionName)
		{
			case 'triggerPublication':
			case 'update':
				$objects = $eventObj->getObjects();

				if (empty($objects[0]))
				{
					return;
				}

				// On update we should get the message passed as parameter
				if (isset($parameters['data']['message']) && !empty($parameters['data']['message']))
				{
					$content = $parameters['data']['message'];
				}
				else
				{
					$content = $objects[0]->getMessage();
				}

				$title = $objects[0]->getTitle();

				if ($this->checkContent($content) || $this->checkContent($title))
				{
					$eventObj->disable();
					//$eventObj->delete();
					//$eventObj->deleteCompletely();
				}
				break;
		}
	}

	/**
	 * Parses the content and return true whether the post should be blocked
	 *
	 * @param   string   $text  The text to be parsed
	 *
	 * @return  boolean  True whether the post should be blocked
	 *
	 * @since   1.0.0
	 */
	private function checkContent($text)
	{
		// Make sure the whitelisted chars does not trigger the checker
		foreach ($this->whitelistedChars as $whitelistedChar)
		{
			$text = str_replace($whitelistedChar, '', $text);
		}
		
		$clearstring = filter_var($text, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_HIGH);
		
		if ($clearstring != $text)
		{
			return true;
		}
		
		return false;
	}
}