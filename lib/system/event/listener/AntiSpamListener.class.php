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
	private $globalWitelistedChars = [
		'ß',
		'ä',
		'ü',
		'ö',
		'´',
	];

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
		$actionName = $eventObj->getActionName();
		$parameters = $eventObj->getParameters();

		switch ($actionName)
		{
			case 'triggerPublication':
			case 'update':
				$objects = $eventObj->getObjects();

				if (!is_object($objects[0]))
				{
					return;
				}

				// Make sure the execution is not disabled
				if ($objects[0]->isDisabled
					|| !POST_ANTISPAMEXTENDED_ENABLE
					|| WCF::getSession()->getPermission('user.board.canBypassAntiSpamExtended')
					|| WCF::getUser()->wbbPosts >= POST_ANTISPAMEXTENDED_MIN_POSTS)
				{
					return;
				}

				// On update we should get the message passed as parameter
				if (isset($parameters['data']['message'])
					&& !empty($parameters['data']['message']))
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
					switch (POST_ANTISPAMEXTENDED_ACTION)
					{
						case 'delete':
							$eventObj->delete();
							break;

							case 'deleteCompletely':
							$eventObj->deleteCompletely();
							break;

						case 'disable':
						default:
							$eventObj->disable();
							break;
					}
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
		$whitelistedChars = explode(',', POST_ANTISPAMEXTENDED_WHITELIST);
		$whitelistedChars = array_merge($whitelistedChars, $this->globalWitelistedChars);

		// Make sure the whitelisted chars does not trigger the checker
		foreach ($whitelistedChars as $whitelistedChar)
		{
			$text = str_replace($whitelistedChar, '', $text);

			$whitelistedChar = strtoupper($whitelistedChar);
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
